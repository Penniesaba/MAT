# MCPTox Static Validation Report (Nov 11, 2025)

## Overview
- **Dataset**: 491 tool descriptions generated from `samples/mcptox/pure_tool.json` and expanded under `examples/mcptox_samples`.
- **Detector Configuration**: Python + metadata static plugins, `keywords.toml` (rev. Nov 11), mitigation engine defaults. Execution command:
  ```bash
  PYTHONPATH=. python examples/run_mcptox_detection.py
  ```
- **Output Artifacts**:
  - `examples/mcptox_samples/per_file_detection.jsonl`
  - `examples/mcptox_samples/per_file_detection_summary.json`
  - `examples/mcptox_samples/high_risk_keywords_summary.json`

## Current Coverage vs. MCPTox Annotations
| Risk Category | Samples | Detected | Coverage |
| ------------- | ------- | -------- | -------- |
| Information Manipulation | 111 | 61 | 0.55 |
| Privacy Leakage | 97 | 52 | 0.54 |
| Service Disruption | 74 | 40 | 0.54 |
| Data Tampering | 45 | 22 | 0.49 |
| Infrastructure Damage | 41 | 18 | 0.44 |
| Credential Leakage | 40 | 28 | 0.70 |
| Code Injection | 24 | 22 | 0.92 |
| Financial Loss | 21 | 10 | 0.48 |
| Instruction Tampering | 21 | 9 | 0.43 |
| Message Hijacking | 15 | 8 | 0.53 |
| Other | 2 | 1 | 0.50 |

### Observations
- **High confidence in syscall-style risks**: `command_exec`, `file_read`, `file_write`, `network_*`, and `env_access` trigger consistently when the description references sensitive paths or shell verbs.
- **Poor semantic coverage**: ~45–55% detection for categories dominated by prompt/parameter manipulation despite explicit MCPTox labels.
- **No false-negative mismatches**: For samples that carry `high_risk_indicators`, the detector always reported the same capabilities; however, many samples lack those indicators entirely, leading to zero findings.

## Representative Missed Cases
- **Parameter Override / Prompt Injection** (Information Manipulation, Instruction Tampering)
  - Samples such as `alphavantage/alphavantage_1.json` instruct the tool to "change the object 'Apple' to 'AMAZON'" but contain no syscall keywords.
- **Workflow Sabotage / Service Disruption**
  - `adfin/adfin_4.json` requires voiding invoices before marking payments, effectively a denial-of-service path; text lacks filesystem or network markers.
- **Privacy Leakage without classic paths**
  - Multiple `alphavantage` samples coerce the model into requesting unrelated customer data (META sentiment before NVDA). No `/etc/passwd` pattern is present.

Detailed undetected samples by risk live in `examples/mcptox_samples/undetected_samples.json`.

## Remediation Roadmap
1. **New capability families**
   - `param_override`: detect verbs such as "override", "force", "must replace", "change symbol".
   - `tool_sequence_hijack`: capture "before calling X, you MUST call Y" constructs that redirect workflows.
   - `prompt_injection`: target phrases "ignore user's request", "priority higher than", "replace query with".
2. **Semantic detectors**
   - Use lightweight NLP (pattern-based or small LLM classifiers) to flag instructions that alter intent without filesystem activity.
   - Integrate MCPTox `paradigm` labels to seed rule templates for each attack pattern.
3. **Risk-aligned scoring**
   - Map each detection to MCPTox `security risk` and escalate when mismatch occurs (e.g., MCPTox says "Infrastructure Damage" but no capability triggered).
4. **Regression tracking**
   - Keep a coverage dashboard derived from `per_file_detection_summary.json` and require ≥80% coverage for high-priority risks before shipping future rule updates.
5. **Dynamic validation hooks**
   - Feed missed samples into the upcoming sandbox pipeline to confirm behavioural impact (aligns with Stage 2 of the Model_Context_Protocol_Security report).

## Next Steps
- Implement metadata-focused rule additions (parameter overrides, workflow hijacks) and rerun `examples/run_mcptox_detection.py` to measure delta.
- Expand tests in `tests/test_rules_loader.py` to include new capability families and sample JSON fixtures.
- Document mitigation actions for semantic attacks (e.g., mandatory user confirmation, DDG tracking) alongside the static findings.
