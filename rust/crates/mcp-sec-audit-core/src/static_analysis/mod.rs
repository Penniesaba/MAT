pub mod facts;

mod agent;
pub(crate) mod category;
mod codeql;
mod component;
mod diff;
mod discovery;
mod evolution;
mod fusion;
pub(crate) mod infer;
pub(crate) mod learning;
mod pipeline;
pub(crate) mod recon;
mod rule;
mod taint;
mod validate;

pub use discovery::{
    DiscoveredFile, DiscoverySummary, ScanLanguage, detect_language, discover_files,
};
pub use facts::{
    ExtractionDiagnostic, JsTsDiagnostic, JsTsExtractionResult, PythonExtractionResult,
    RustExtractionResult, extract_js_ts_facts, extract_python_facts, extract_rust_facts,
    extract_static_facts,
};
pub use pipeline::{
    StaticScanContext, run_static_scan, run_static_scan_inner, run_static_scan_with_progress,
};
