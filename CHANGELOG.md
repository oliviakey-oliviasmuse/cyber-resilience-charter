# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-09-02

### Phase 1 (Define) — Final

This is the first formal release of the Cyber Resilience Project Charter for the EV cell manufacturing engagement. It is ready for the CISO G1 tollgate review.

### Added

#### Strategic (charter)
- **Project Charter** — 8 sections + 2 appendices, Six Sigma aligned (Z ≥ 6.0, Cpk ≥ 2.0)
- **Executive Summary** — engagement at a glance, business case, strategic alignment, target outcomes (MBB-derived sub-process capability targets)
- **Business Case & Financial Exposure** — P × E × M model, 5 exposure classes (downtime, silent corruption, IP, regulatory, safety tail), COPQ, multi-site enterprise protected value
- **CISO Strategic Alignment** — role architecture, RACI matrix, tollgate sign-off authority, escalation matrix, **Data-Access Governance (the Data-Blind Protocol)**
- **DMAIC Methodology** — Define, Measure, Analyse, Improve, Control phases; **Cyber-FMEA top 12** with S scores recalibrated to 10 for all silent corruption modes
- **Implementation Roadmap** — 12-week Gantt with 3 parallel tracks (Architecture / Data & Metrics / Automation), cross-track dependencies, Track B critical path, 4 risk-based decision points
- **Continuation & Standard Work** — Standard Work (weekly / monthly / quarterly / annual), **13 Cyber-Kaizen triggers** (10 routine + 3 structural), 5-level Maturity Scoring, Cross-Site Replication plan
- **CISO Governance Cycle** — 4 governance components (Dashboard, Bi-weekly, Bi-annual, Annual), **8-tile Executive Dashboard** with GREEN/AMBER/RED alert system
- **Constraints & Risks** — 5 constraint categories, 10 assumptions, **8-risk register** (4 active-mitigation, 4 monitor), 7 residual risks, 10 entropy defence mechanisms
- **CISO Elevator Pitch** — 3 variants (CISO Opening, Board Pitch, 30-Second) + 2 sub-variants (OEM customer, IT Security peer), with three pain points (silent corruption, IP exfiltration, COPQ) leading the CISO and Board variants
- **CISO Executive Dashboard Mockup** — text + interactive HTML, G5 illustrative state, click-to-drill-down on all 8 tiles

#### Six Sigma targets (Z ≥ 6.0)
- Cpk ≥ 2.0 across every sub-process
- MTTD known signatures ≤ 2 min (SOC Triage Agent)
- MTTD novel OT anomalies ≤ 10 min (OT Anomaly Detection Agent)
- MTTR hard stop ≤ 1 hour (IR Automation Agent + SMED recovery rig)
- MTTR OT compromise ≤ 8 hours
- Patch compliance ≥ 99% within maintenance windows
- FMEA RPN reduction ≥ 80% across top 10 cyber failure modes

#### Operational (implementation)
- **4 AI agents** (Layer 3) — SOC Triage, OT Anomaly Detection, IR Automation, Threat Intel Correlation; production-quality Python with CISO kill switch on every agent
- **2 Poka-Yoke enforcers** — Parameter Drift Interlock (fail-closed auto-isolation), Cryptographic Recipe Signer (Ed25519 + HSM-backed, PLC verifier)
- **SMED Recovery Orchestrator** — pre-staged immutable backups, restore rigs, golden images, 3 default playbooks (ransomware, formation charging, electrolyte dosing)
- **Anonymised Data Lake Query Interface** — ALLOWED/RESTRICTED pattern enforcement, bounded queries, audit-logged
- **Test suites** — 100% pass on safety-critical tests, fail-closed verification
- **Deployment script** — systemd-based, pre-flight checks, dry-run mode, per-track filter
- **Documentation** — Architecture, Data Flow, Operations, Security Model

#### Public deployments (3 live URLs)
- Full charter bundle: https://87x1siaib1okk.space.minimax.io
- Standalone CISO dashboard: https://6z9fkk0oehsun.space.minimax.io
- Standalone CISO dashboard (additional): https://vmn4dy5p05641.space.minimax.io

### Notes

- This is the **first** release; no prior versions exist
- The capability target is **Z ≥ 6.0** (theoretical Six Sigma), not 4.5σ or 5σ
- The implementation is **reference code**; production deployment requires adaptation to the specific OT environment
- The public URLs are anonymised; no internal network configurations, IP addresses, or proprietary system details are exposed
- The Data-Blind Protocol (#3.5 of the charter) is enforced at schema, query, and application levels — GBs and AI agents cannot access raw data even if they tried

### Roadmap

| Version | Phase | Target |
|---|---|---|
| 1.0.0 | Phase 1 (Define) | 2026-09-02 ✓ |
| 1.1.0 | Phase 2 (Measure) — data lake deployment, baseline measurement, capability validation | Pending G1 sign-off |
| 2.0.0 | Phase 3 (Analyse) — FMEA finalisation, root-cause analysis, control-point design | Pending G2 sign-off |
| 3.0.0 | Phase 4 (Improve) — control deployment, AI agent integration, SMED activation | Pending G3 sign-off |
| 4.0.0 | Phase 5 (Control) — SPC live, Standard Work embedded, handover to Operations | Pending G4 sign-off |
| 5.0.0 | Continuation — Site 2 G5, cross-site replication begins | TBD |
| 6.0.0 | Maturity Level 4 sustained, Site 3 G5, enterprise benchmark initiated | TBD |
| 7.0.0 | Maturity Level 5 (Optimising), all 5 sites at Level 4+, enterprise benchmark complete | TBD |
