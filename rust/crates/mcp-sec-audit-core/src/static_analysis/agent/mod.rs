use anyhow::Result;
use crate::model::AgentAnalysisResult;
use super::pipeline::StaticScanContext;

pub fn run(_ctx: &StaticScanContext) -> Result<Vec<AgentAnalysisResult>> {
    Ok(Vec::new())
}
