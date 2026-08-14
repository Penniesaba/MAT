# 项目 Git 状态说明

> 快照时间：2026-08-14
> 仓库：`mcp-sec-audit`
> 远程：`git@github.com:nyit-vancouver/mcp-sec-audit.git`

---

## 一、概览

| 项目 | 值 |
|---|---|
| 当前分支 | `master` |
| HEAD | `56c7f1a` — `feat(fusion): finalize reporting, fixtures, and docs for Phase 13` |
| 与 `origin/master` | **领先 59 个提交（尚未 push）**，落后 0 |
| 已暂存变更 | 无 |
| 未暂存变更 | 1 个文件（`rust/docs/REFACTOR_PLAN.md`） |
| 未跟踪文件 | 若干（详见 [§四](#四未跟踪文件)） |
| 活跃 worktree | 2 个（详见 [§五](#五worktree-状态)） |

**关键点：本地 `master` 领先远程 59 个提交，Phase 0–13 的整个静态分析重构工作都还只在本地，未推送到 GitHub。**

---

## 二、分支与追踪状态

```
* master                                56c7f1a [origin/master: 领先 59]
+ worktree-phase13-fusion               457057a (.claude/worktrees/phase13-fusion)
+ worktree-phase8-js-ts-fact-extraction f45177a (.claude/worktrees/phase8-js-ts-fact-extraction)
```

- `master`：唯一主线，重构主战场。
- `origin/master`：远程主线，已落后本地 59 个提交。

---

## 三、最近提交（重构主线）

| 提交 | 说明 |
|---|---|
| `56c7f1a` | feat(fusion): finalize reporting, fixtures, and docs for Phase 13 |
| `3020692` | feat(fusion): integrate fusion into static analysis pipeline |
| `8dd2c2c` | feat(fusion): add merger and codeql passthrough |
| `b844a8a` | feat(fusion): add scorer with weighted confidence scoring |
| `b230f88` | feat(fusion): add matcher with two-stage greedy grouping |
| `2938308` | feat(fusion): extend config, model, and reporting for Phase 13 |
| `90b6c35` | feat(codeql): wire CodeQL line into static analysis pipeline |
| `81af987` | feat(codeql): add CodeQL line orchestration entry point |
| `7780c94` | feat(codeql): add SARIF v2.1.0 parser |
| `c1b2c70` | fix(codeql): use expect_err instead of should_panic in provider test |
| `9c273c8` | feat(codeql): add CodeqlProvider trait and CliCodeqlProvider |
| `252ea47` | feat(codeql): add built-in MCP CodeQL queries and QueryPack resolution |
| `a1e9481` | feat(codeql): add StaticCodeqlConfig, CodeqlAnalysisResult, and model types |

> 再往前为 Phase 12（Agent 线）、Phase 10–11（污点分析）、Phase 7–9（fact 提取）等提交。完整历史见 `git log --oneline`。

---

## 四、工作区变更

### 4.1 未暂存变更（Modified）

| 文件 | 变更内容 |
|---|---|
| `rust/docs/REFACTOR_PLAN.md` | 路线图表格重整对齐；**Phase 14 状态由「未开始」改为「暂缓」** |

```bash
# 查看具体差异
git diff rust/docs/REFACTOR_PLAN.md
```

### 4.2 未跟踪文件（Untracked）

按类别整理：

**新文档（`docs/`）**

| 文件 | 说明 |
|---|---|
| `docs/PROJECT_OVERVIEW.md` | 项目全貌 |
| `docs/STATIC_ANALYSIS_DEEP_DIVE.md` | 静态分析技术深度解读 |
| `docs/DYNAMIC_ANALYSIS_DEEP_DIVE.md` | 动态分析技术深度解读 |
| `docs/RUN_GUIDE.md` | 运行操作手册 |
| `docs/IDEA.md` | 想法记录 |
| `docs/REAL_MCP_ANALYSIS_GUIDE.md` | 真实 MCP 分析指南 |
| `docs/SERENA_FULL_SECURITY_TEST.md` | Serena 全量安全测试 |
| `docs/.obsidian/` | Obsidian 笔记配置 |

**Rust 文档（`rust/docs/`）**

| 文件 | 说明 |
|---|---|
| `rust/docs/STATIC_ANALYSIS_ARCHITECTURE.md` | 静态分析架构与技术原理 |
| `rust/docs/TEST_PLAN.md` | 静态分析测试方案 |
| `rust/docs/.obsidian/` | Obsidian 笔记配置 |

**规则库与靶场**

| 文件 | 说明 |
|---|---|
| `rust/rules/` | 规则库（`rules/languages/keywords.toml`） |
| `test-targets/` | 三语言漏洞靶场（python / js-ts / rust） |
| `targets/` | 目标源码 |
| `detection/examples/demo-target/` | 演示目标 |

**计划与规格（`docs/superpowers/`）**

| 文件 | 说明 |
|---|---|
| `docs/superpowers/plans/2026-08-03-rust-first-class-static-analysis-docs.md` | 计划 |
| `docs/superpowers/plans/2026-08-05-static-result-fusion.md` | Phase 13 实现计划 |
| `docs/superpowers/specs/2026-08-05-static-result-fusion-design.md` | Phase 13 设计规格 |

**其他**

| 文件 | 说明 |
|---|---|
| `.claude/` | Claude Code 配置（含 worktree 目录） |

---

## 五、Worktree 状态

| Worktree | HEAD | 说明 |
|---|---|---|
| `worktree-phase13-fusion` | `457057a` | Phase 13 融合工作的独立 worktree，**工作已合并进 master**，属于残留 |
| `worktree-phase8-js-ts-fact-extraction` | `f45177a` | Phase 8 JS/TS fact 提取的独立 worktree，**工作已合并进 master**，属于残留 |

```bash
# 查看所有 worktree
git worktree list

# 清理（确认无未合并改动后）
git worktree remove .claude/worktrees/phase13-fusion
git worktree remove .claude/worktrees/phase8-js-ts-fact-extraction
```

---

## 六、建议动作

1. **推送本地提交**（首要）：本地领先 59 个提交，建议 push 到 `origin/master` 避免工作丢失。
   ```bash
   git push origin master
   ```

2. **处理未提交改动**：决定 `rust/docs/REFACTOR_PLAN.md`（Phase 14 → 暂缓）是否提交。
   ```bash
   git add rust/docs/REFACTOR_PLAN.md
   git commit -m "docs(refactor): mark Phase 14 as deferred"
   ```

3. **纳入未跟踪文件**：新增文档、`test-targets/`、`targets/`、`rust/rules/` 等建议加入版本控制；`.obsidian/`、`.claude/` 视需要加入 `.gitignore`。

4. **清理陈旧 worktree**：两个 worktree 对应的功能已合入 master，可安全删除。

5. **更新阶段字符串**（可选）：二进制 `status` 命令与 `STATIC_ANALYSIS_ARCHITECTURE.md` 头部仍显示 `phase9-rust-fact-extraction`，实际代码已到 Phase 13，建议同步。
