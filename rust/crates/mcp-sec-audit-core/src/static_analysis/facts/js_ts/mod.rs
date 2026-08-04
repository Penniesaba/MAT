use crate::model::Fact;

use super::ExtractionDiagnostic;

#[allow(dead_code)]
mod calls;
#[allow(dead_code)]
mod functions;
#[allow(dead_code)]
mod imports;
#[allow(dead_code)]
mod sinks;

#[allow(unused_imports)]
pub(crate) use calls::{callee_to_string, extract_call_args, resolve_callee};

#[allow(unused_imports)]
pub(crate) use functions::{
    build_qualified_name, create_function_fact, params_from_fn,
};

#[allow(unused_imports)]
pub(crate) use imports::{
    extract_destructured_require, extract_esm_import, extract_require_call,
};

#[allow(unused_imports)]
pub(crate) use sinks::check_sink;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsTsDiagnostic {
    Fatal { file: String, message: String },
    NonFatal {
        file: String,
        line: u32,
        kind: String,
        message: String,
    },
}

impl From<JsTsDiagnostic> for ExtractionDiagnostic {
    fn from(d: JsTsDiagnostic) -> Self {
        match d {
            JsTsDiagnostic::Fatal { file, message } => ExtractionDiagnostic {
                file,
                line: 0,
                kind: "fatal_parse_error".to_string(),
                message,
            },
            JsTsDiagnostic::NonFatal {
                file,
                line,
                kind,
                message,
            } => ExtractionDiagnostic { file, line, kind, message },
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct JsTsExtractionResult {
    pub facts: Vec<Fact>,
    pub diagnostics: Vec<JsTsDiagnostic>,
}

impl JsTsExtractionResult {
    pub fn empty() -> Self {
        Self {
            facts: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    pub fn has_fatal(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| matches!(d, JsTsDiagnostic::Fatal { .. }))
    }
}
