//! Batch configuration and per-repository override merging (v5 parallel
//! multi-repository analysis).
//!
//! This module is pure data + pure functions: it defines the batch-file
//! schema and the deep-merge that turns a shared base config plus one
//! repository's overrides into a fully-resolved per-repo [`RuntimeConfig`].
//! The governor, learning bus, and orchestrator build on top of it.

mod config;
mod governor;

pub use config::{
    BatchConfig, BatchSettings, LimitsConfig, RepoConfig, load_batch_config, merge_repo_config,
    parse_batch_config_toml,
};
pub use governor::{ResourceClass, ResourceGovernor};
