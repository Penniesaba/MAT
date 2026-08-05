pub mod facts;

mod agent;
mod codeql;
mod discovery;
// TODO(fusion): remove `#[allow(dead_code)]` once Task 5 wires the fusion
// pipeline into `pipeline.rs`; until then the matcher is built but uncalled.
#[allow(dead_code)]
pub(crate) mod fusion;
mod pipeline;
mod rule;
mod taint;

pub use discovery::{
    DiscoveredFile, DiscoverySummary, ScanLanguage, detect_language, discover_files,
};
pub use facts::{
    ExtractionDiagnostic, JsTsExtractionResult, JsTsDiagnostic, PythonExtractionResult,
    RustExtractionResult, extract_js_ts_facts, extract_python_facts, extract_rust_facts,
    extract_static_facts,
};
pub use pipeline::{StaticScanContext, run_static_scan};
