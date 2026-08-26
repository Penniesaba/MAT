//! Benchmark scoring for known-vulnerable MCP repositories (v5).

pub mod ground_truth;
pub mod manifest;
pub mod report;
pub mod scorer;

pub use manifest::{BenchManifest, RepoEntry, dedupe_commits, load_manifest, to_batch_config};
