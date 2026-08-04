pub mod facts;

mod discovery;
mod lines;
mod pipeline;
mod rule;

pub use discovery::{
    DiscoveredFile, DiscoverySummary, ScanLanguage, detect_language, discover_files,
};
pub use facts::{
    ExtractionDiagnostic, PythonExtractionResult, JsTsExtractionResult, JsTsDiagnostic,
    extract_python_facts, extract_js_ts_facts, extract_static_facts,
};
pub use pipeline::{StaticScanContext, run_static_scan};
