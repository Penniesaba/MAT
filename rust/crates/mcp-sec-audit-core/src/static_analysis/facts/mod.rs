use std::path::Path;

use crate::model::Fact;

mod ids;
mod js_ts;
mod pipeline;
mod python;
mod rust;

pub use ids::{
    make_assign_id, make_call_id, make_entrypoint_id, make_fact_id, make_function_id,
    make_import_id, make_sink_id, make_source_id,
};
pub use js_ts::{extract_js_ts_facts, JsTsDiagnostic, JsTsExtractionResult};
pub use pipeline::extract_static_facts;
pub use python::extract_python_facts;
pub use rust::{extract_rust_facts, RustExtractionResult};

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

// ---------------------------------------------------------------------------
// Shared utility functions used by all language extractors
// ---------------------------------------------------------------------------

/// Compute (line, column) from a byte offset into source text.
/// Line numbers are 1-based, column numbers are 0-based.
pub(crate) fn line_col_for_offset(source: &str, offset: u32) -> (u32, u32) {
    let offset = offset as usize;
    let prefix = &source[..offset.min(source.len())];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() as u32 + 1;
    let column = prefix
        .rsplit('\n')
        .next()
        .map(|item| item.chars().count() as u32)
        .unwrap_or(0);
    (line, column)
}

/// Extract source text snippet for a byte range.
pub(crate) fn snippet_for_range(source: &str, start: u32, end: u32) -> String {
    let start = start as usize;
    let end = end as usize;
    source
        .get(start.min(source.len())..end.min(source.len()))
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Stable sort key for facts so they appear in line order within the output.
pub(crate) fn fact_sort_key(fact: &Fact) -> String {
    match fact {
        Fact::Function(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Import(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Entrypoint(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Call(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Sink(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Source(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Assign(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Dataflow(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::RuntimeEvent(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Finding(item) => format!("{:010}:{}", item.base.line, item.base.id),
    }
}

pub(crate) fn display_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

