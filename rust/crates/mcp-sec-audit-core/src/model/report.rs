use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::EvidenceSource;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityFinding {
    pub name: String,
    pub description: String,
    pub score_weight: f64,
    pub confidence: f64,
    pub sources: Vec<EvidenceSource>,
    pub evidence: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionResult {
    pub server_name: String,
    pub findings: Vec<CapabilityFinding>,
    pub total_score: f64,
    pub risk_level: String,
    pub mitigations: Vec<String>,
    pub notes: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_result_roundtrips_json() {
        let result = crate::fixtures::synthetic_detection_result();
        let json = serde_json::to_string(&result).expect("serialize detection result");
        let decoded: DetectionResult =
            serde_json::from_str(&json).expect("deserialize detection result");

        assert_eq!(decoded, result);
    }

    #[test]
    fn evidence_source_uses_python_compatible_values() {
        assert_eq!(
            serde_json::to_value(EvidenceSource::Static).expect("serialize evidence source"),
            serde_json::json!("static")
        );
        assert_eq!(
            serde_json::to_value(EvidenceSource::Dynamic).expect("serialize evidence source"),
            serde_json::json!("dynamic")
        );
    }
}
