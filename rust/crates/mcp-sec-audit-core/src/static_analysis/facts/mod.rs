use std::path::Path;

use crate::Fact;

mod ids;
mod js_ts;
mod pipeline;
mod python;

pub use ids::{
    make_assign_id, make_call_id, make_entrypoint_id, make_fact_id, make_function_id,
    make_import_id, make_sink_id, make_source_id,
};
pub use js_ts::{extract_js_ts_facts, JsTsDiagnostic, JsTsExtractionResult};
pub use pipeline::extract_static_facts;
pub use python::extract_python_facts;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionDiagnostic {
    pub file: String,
    pub line: u32,
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PythonExtractionResult {
    pub facts: Vec<Fact>,
    pub diagnostics: Vec<ExtractionDiagnostic>,
}

impl PythonExtractionResult {
    pub fn empty() -> Self {
        Self {
            facts: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}

pub(crate) fn display_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

