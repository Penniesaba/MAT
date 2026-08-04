use crate::model::Fact;

use super::ExtractionDiagnostic;

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
