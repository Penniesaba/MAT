//! Per-resource-class concurrency limiting (v5 parallel multi-repository
//! analysis).
//!
//! A [`ResourceGovernor`] owns one tokio [`Semaphore`] per [`ResourceClass`].
//! A batch of repository scans acquires a permit for the class of work it is
//! about to do, so that CodeQL database builds, LLM agent invocations, and
//! CPU-bound phases each stay within the [`LimitsConfig`] budget rather than
//! over-subscribing the machine.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::LimitsConfig;

/// The three hardware/process budgets a batch run must respect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceClass {
    /// CodeQL CLI processes (`database create`) — memory-heavy, keep serial.
    Codeql,
    /// Agent (LLM CLI) processes — latency-bound and rate-limited.
    Agent,
    /// CPU-bound phases (rule / taint / fusion / fact extraction).
    Cpu,
}

/// Per-class concurrency limiter backed by one tokio [`Semaphore`] each.
#[derive(Clone)]
pub struct ResourceGovernor {
    codeql: Arc<Semaphore>,
    agent: Arc<Semaphore>,
    cpu: Arc<Semaphore>,
}

impl ResourceGovernor {
    /// Builds a governor from the per-class budgets in `limits`.
    ///
    /// A `0` budget is clamped to `1`: a closed (zero-permit) semaphore would
    /// never hand out a permit, so any class must admit at least one worker.
    pub fn new(limits: &LimitsConfig) -> Self {
        Self {
            codeql: Arc::new(Semaphore::new(limits.codeql.max(1))),
            agent: Arc::new(Semaphore::new(limits.agent.max(1))),
            cpu: Arc::new(Semaphore::new(limits.cpu.max(1))),
        }
    }

    /// Acquires a permit for `class`, awaiting until one is available.
    ///
    /// # 防死锁不变量
    /// 调用方任一时刻最多持有一个类别的许可，且绝不在持有 A 类许可时申请 B 类许可。
    /// 因许可从不跨类别持有，环形等待在结构上不可能出现。
    /// 实现方式：每个阶段独立作用域，靠 OwnedSemaphorePermit 的 RAII 释放。
    pub async fn acquire(&self, class: ResourceClass) -> OwnedSemaphorePermit {
        let sem = match class {
            ResourceClass::Codeql => self.codeql.clone(),
            ResourceClass::Agent => self.agent.clone(),
            ResourceClass::Cpu => self.cpu.clone(),
        };
        // The semaphore is never closed, so `acquire_owned` cannot fail; a
        // closed semaphore here would be a programmer error, hence the expect.
        sem.acquire_owned()
            .await
            .expect("resource governor semaphore closed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::task::JoinSet;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn governor_caps_peak_concurrency_per_class() {
        let gov = ResourceGovernor::new(&LimitsConfig { codeql: 1, agent: 1, cpu: 2 });
        let peak = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(AtomicUsize::new(0));
        let mut set = JoinSet::new();
        for _ in 0..8 {
            let (gov, peak, live) = (gov.clone(), peak.clone(), live.clone());
            set.spawn(async move {
                let _p = gov.acquire(ResourceClass::Codeql).await;
                let n = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
        while set.join_next().await.is_some() {}
        assert_eq!(peak.load(Ordering::SeqCst), 1, "codeql must be serialized");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn distinct_classes_do_not_block_each_other() {
        let gov = ResourceGovernor::new(&LimitsConfig { codeql: 1, agent: 1, cpu: 2 });

        // Holding a codeql permit must not prevent acquiring a cpu permit:
        // classes are independent, so no cross-class wait is possible.
        let _codeql = gov.acquire(ResourceClass::Codeql).await;
        let _cpu = gov.acquire(ResourceClass::Cpu).await;
        let _agent = gov.acquire(ResourceClass::Agent).await;
    }
}
