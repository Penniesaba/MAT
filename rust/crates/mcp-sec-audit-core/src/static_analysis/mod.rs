pub mod facts;

mod agent;
pub(crate) mod category;
mod codeql;
mod diff;
mod discovery;
mod fusion;
pub(crate) mod infer;
pub(crate) mod learning;
mod pipeline;
pub(crate) mod recon;
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
pub use pipeline::{StaticScanContext, run_static_scan, run_static_scan_with_progress};
