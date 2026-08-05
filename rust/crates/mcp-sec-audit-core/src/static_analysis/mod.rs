pub mod facts;

mod agent;
mod discovery;
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
