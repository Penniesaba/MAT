# Detection & Mitigation Roadmap

This document outlines the long-term plan for a modular MCP security analysis library that begins with static detection and scales toward knowledge-assisted and dynamic defenses.

## Phase 1 – Static Detection MVP
- Scaffold the `detection` package with core domain models, plugin interfaces, reporting utilities, and a CLI entry point.
- Deliver Python static analysis via keyword/AST rules defined in YAML, scoring risk based on capability weights, and generating mitigation suggestions.
- Ship unit tests covering rule parsing, scoring math, and JSON/markdown report rendering.

## Phase 2 – Multi-language & Knowledge Base
- Add TypeScript static scanning through a dedicated plugin while reusing the shared scoring engine.
- Establish a structured `knowledge/` store informed by `Model_Context_Protocol_Security.pdf`, capturing threat patterns, mitigation playbooks, and example incidents.
- Introduce a report aggregator that merges findings from any combination of pipelines.

## Phase 3 – RAG Integration & Dynamic Sandbox
- Define a `KnowledgeService` interface and implement a local vector-backed retriever that enriches reports with contextual mitigations.
- Create a `SandboxProvider` abstraction (Docker, Firecracker, etc.), implement a baseline runner that observes tool behavior, and fold dynamic evidence into the scoring model.
- Update mitigation logic to differentiate recommendations by evidence source (static vs. dynamic vs. RAG).

## Phase 4 – CI Integration & Policy Templates
- Publish CLI/CI recipes (e.g., GitHub Action) that execute scans and attach reports to pull requests.
- Maintain curated `mitigation/policy_templates/` describing container profiles, network controls, and logging requirements keyed to capability bundles.
- Track metrics (coverage, false positives, mitigation adoption) to guide iterative rule tuning.

## Extensibility Principles
- **Plugin System:** `plugins/{static,dynamic,rag}` register analyzers without altering the core orchestrator.
- **Session Context:** `DetectionSession` shares configuration, intermediate findings, and knowledge hints across pipelines.
- **Config-Driven Rules:** Keywords, weights, and chaining heuristics live in YAML for rapid updates.
- **Decoupled Reporting:** `ReportBuilder` and `MitigationEngine` consume normalized capability findings, enabling new evidence sources to integrate cleanly.
- **Future Hooks:** Reserve interfaces for LLM-based tool description parsing, behavioral anomaly detection, and automated policy generation.

## Differentiation from MCP-Guard
- **Composable Pipelines:** Our plugin-first architecture lets teams mix static, dynamic, and knowledge-driven analyzers without a fixed three-stage flow, fitting heterogeneous MCP deployments.
- **Mitigation-Centric Output:** The roadmap elevates `MitigationEngine` and policy templates so every finding maps to actionable containment steps, closing the gap between detection and ops hardening.
- **Transparent Scoring:** YAML-defined weights and evidence trails keep risk calculations auditable, allowing security engineers to recalibrate thresholds per project.
- **Knowledge Store Reuse:** `knowledge/` captures curated guidance from internal papers and community reports, powering future RAG enrichments beyond pure LLM arbitration.
