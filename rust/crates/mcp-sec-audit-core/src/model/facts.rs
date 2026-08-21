use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    Confidence, EntryPointKind, FindingStatus, ImportKind, PathStepKind, RuntimeEventKind, Severity,
};

pub const SCHEMA_VERSION: &str = "1.0.0";

pub type JsonMap = BTreeMap<String, Value>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactBase {
    pub id: String,
    pub file: String,
    pub line: u32,
    pub extractor: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamInfo {
    pub name: String,
    pub annotation: Option<String>,
    pub default: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallArg {
    pub index: u32,
    pub expr: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallKwarg {
    pub expr: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallResolution {
    pub import_alias: Option<String>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPointEvidence {
    pub kind: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathStep {
    pub kind: PathStepKind,
    pub line: u32,
    pub name: Option<String>,
    pub function: Option<String>,
    #[serde(rename = "from")]
    pub from_: Option<String>,
    pub to: Option<String>,
    pub snippet: Option<String>,
    pub call_id: Option<String>,
    pub arg_index: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Fact {
    Function(FunctionFact),
    Import(ImportFact),
    Entrypoint(EntryPointFact),
    Call(CallFact),
    Sink(SinkFact),
    Sanitizer(SanitizerFact),
    Source(SourceFact),
    Assign(AssignFact),
    Dataflow(DataFlowFact),
    RuntimeEvent(RuntimeEventFact),
    Finding(FindingFact),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionFact {
    #[serde(flatten)]
    pub base: FactBase,
    pub language: String,
    pub name: String,
    pub qualified_name: String,
    pub end_line: u32,
    pub params: Vec<ParamInfo>,
    pub decorators: Vec<String>,
    pub docstring: Option<String>,
    pub return_type: Option<String>,
    pub enclosing_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportFact {
    #[serde(flatten)]
    pub base: FactBase,
    pub language: String,
    pub module: String,
    pub imported_name: Option<String>,
    pub alias: Option<String>,
    pub kind: ImportKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPointFact {
    #[serde(flatten)]
    pub base: FactBase,
    pub kind: EntryPointKind,
    pub name: String,
    pub function_id: String,
    pub evidence: Option<EntryPointEvidence>,
    pub params: Vec<String>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallFact {
    #[serde(flatten)]
    pub base: FactBase,
    pub caller: String,
    pub callee: String,
    pub normalized_callee: Option<String>,
    pub column: Option<u32>,
    pub end_line: Option<u32>,
    pub snippet: String,
    pub args: Vec<CallArg>,
    pub kwargs: BTreeMap<String, CallKwarg>,
    pub resolution: Option<CallResolution>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SinkFact {
    #[serde(flatten)]
    pub base: FactBase,
    pub call_id: String,
    pub category: String,
    pub rule_id: String,
    pub sink_name: String,
    pub severity_base: Severity,
    pub reason: String,
    pub conditions: JsonMap,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFact {
    #[serde(flatten)]
    pub base: FactBase,
    pub kind: String,
    pub function_id: String,
    pub name: String,
    pub confidence: Confidence,
    /// For model-driven sources: the call whose result is tainted. `None` for
    /// structurally-detected sources (MCP tool parameters, entrypoints).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizerFact {
    #[serde(flatten)]
    pub base: FactBase,
    pub call_id: String,
    pub sanitizer_name: String,
    /// Sink categories neutralized (a `"*"` entry neutralizes everything).
    pub neutralizes: Vec<String>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignFact {
    #[serde(flatten)]
    pub base: FactBase,
    pub function_id: String,
    pub target: String,
    pub value: String,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFlowFact {
    #[serde(flatten)]
    pub base: FactBase,
    pub source_id: String,
    pub sink_id: String,
    pub path: Vec<PathStep>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEventFact {
    #[serde(flatten)]
    pub base: FactBase,
    pub kind: RuntimeEventKind,
    pub syscall: Option<String>,
    pub command: Option<String>,
    pub pid: Option<u32>,
    pub container_id: Option<String>,
    pub timestamp: Option<String>,
    pub correlated_entrypoint: Option<String>,
    pub correlated_sink: Option<String>,
    pub confidence: Option<Confidence>,
    pub ustack: Option<Vec<String>>,
    pub script_file: Option<String>,
    pub script_line: Option<u32>,
    pub logical_function: Option<String>,
    pub command_args: Option<Vec<String>>,
    pub target_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingFact {
    #[serde(flatten)]
    pub base: FactBase,
    pub title: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub status: FindingStatus,
    pub entrypoint_id: Option<String>,
    pub sink_id: Option<String>,
    pub call_chain: Vec<JsonMap>,
    pub dataflows: Vec<String>,
    pub dynamic_evidence: Vec<String>,
    pub evidence: Vec<String>,
    pub recommendation: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_fact_roundtrips_json() {
        let fact = crate::fixtures::synthetic_finding_fact();
        let json = serde_json::to_string(&fact).expect("serialize finding fact");
        let decoded: FindingFact = serde_json::from_str(&json).expect("deserialize finding fact");

        assert_eq!(decoded, fact);
    }

    #[test]
    fn tagged_fact_roundtrips_json() {
        let fact = Fact::Finding(crate::fixtures::synthetic_finding_fact());
        let json = serde_json::to_string(&fact).expect("serialize tagged fact");
        let decoded: Fact = serde_json::from_str(&json).expect("deserialize tagged fact");

        assert_eq!(decoded, fact);
    }

    #[test]
    fn path_step_uses_python_compatible_from_field() {
        let step = PathStep {
            kind: PathStepKind::Assign,
            line: 10,
            name: None,
            function: None,
            from_: Some("cmd".to_string()),
            to: Some("command".to_string()),
            snippet: Some("command = cmd".to_string()),
            call_id: None,
            arg_index: None,
        };
        let value = serde_json::to_value(step).expect("serialize path step");

        assert_eq!(value["from"], serde_json::json!("cmd"));
        assert!(value.get("from_").is_none());
    }

    #[test]
    fn enum_values_match_python_schema() {
        assert_eq!(
            serde_json::to_value(Severity::Critical).expect("serialize severity"),
            serde_json::json!("critical")
        );
        assert_eq!(
            serde_json::to_value(Confidence::Medium).expect("serialize confidence"),
            serde_json::json!("medium")
        );
        assert_eq!(
            serde_json::to_value(FindingStatus::RuntimeOnly).expect("serialize finding status"),
            serde_json::json!("runtime_only")
        );
        assert_eq!(
            serde_json::to_value(RuntimeEventKind::NetworkConnect)
                .expect("serialize runtime event kind"),
            serde_json::json!("network_connect")
        );
    }
}
