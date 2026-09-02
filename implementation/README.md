# Cyber Resilience Implementation — Phase 4 (Improve)

**Six Sigma-aligned (Z ≥ 6.0) reference implementations for the OT cyber resilience engagement.**

This folder contains the actual code the 19 Green Belts will deploy in **Phase 4 (Improve, Weeks 8–10)** of the 12-week engagement. Every component maps to a specific architectural choice in the Phase 1 charter (§4) and is sized for Six Sigma (Cpk ≥ 2.0) capability.

## Folder structure

```
implementation/
├── README.md                           ← you are here
├── 00-specifications/                  ← contracts, interfaces, schemas
│   ├── ai-agents/                      ← 4 AI agent specs (SOC, OT Anomaly, IR, Threat Intel)
│   ├── poka-yoke/                      ← 5 Poka-Yoke principle specs
│   ├── smed/                            ← SMED recovery rig spec
│   ├── data-lake/                       ← anonymised data lake schema + interfaces
│   ├── dashboard/                       ← Executive Dashboard tile contracts
│   └── fmea/                            ← FMEA control plan spec
├── 01-reference-implementations/        ← production-quality reference code
│   ├── ai-agents/                       ← 4 AI agents (Python)
│   ├── poka-yoke/                       ← 5 Poka-Yoke enforcers (Python)
│   ├── smed/                            ← SMED recovery rig (Python)
│   ├── data-lake/                       ← query interface + anonymisation spec
│   ├── dashboard/                       ← Executive Dashboard (HTML/JS)
│   ├── fmea/                            ← FMEA control plan
│   ├── standard-work/                   ← weekly/monthly/quarterly routines
│   └── kaizen/                          ← 13 Kaizen trigger router + A3 generator
├── 02-tests/                            ← pytest + Jest test suites
├── 03-deployment/                       ← deployment scripts (CI/CD, K8s, etc.)
└── 04-documentation/                    ← engineering docs
    ├── ARCHITECTURE.md
    ├── DATA-FLOW.md
    ├── SECURITY-MODEL.md
    └── OPERATIONS.md
```

## Component map (engagement → implementation)

| Charter section | Component | Implementation |
|---|---|---|
| §3.5 Data-Access Governance | Anonymised data lake | `00-specifications/data-lake/`, `01-reference-implementations/data-lake/` |
| §4.5.2 Digital 5C | Sort, Straighten, Shine, Standardise, Sustain | `03-deployment/` (legacy protocol decommission, DMZ setup, code standards) |
| §4.5.3 Cyber Poka-Yoke | 5 structural principles | `00-specifications/poka-yoke/`, `01-reference-implementations/poka-yoke/` |
| §4.5.4 SMED for Disaster Recovery | Internal→External step conversion | `00-specifications/smed/`, `01-reference-implementations/smed/` |
| §4.5.5 AI-Augmented Layer 3 | 4 autonomous agents | `00-specifications/ai-agents/`, `01-reference-implementations/ai-agents/` |
| §4.6.2 SPC | p-chart, I-MR chart, u-chart, Cpk trend | `01-reference-implementations/dashboard/spc/` |
| §4.6.3 Control Plan | Automated triggers + isolation | `01-reference-implementations/fmea/` |
| §6.2 Standard Work | Weekly/monthly/quarterly/annual routines | `01-reference-implementations/standard-work/` |
| §6.3 Kaizen Triggers | 13 triggers + A3 generator | `01-reference-implementations/kaizen/` |
| §7.2 Executive Dashboard | 8-tile dashboard + drill-down | `01-reference-implementations/dashboard/` |

## Six Sigma alignment

Every component is designed to support the engagement-level target of **Z ≥ 6.0** (theoretical Six Sigma):

- **Cpk ≥ 2.0** on every sub-process
- **MTTD known signatures ≤ 2 min** (AI-augmented SOC Triage)
- **MTTD novel OT anomalies ≤ 10 min** (AI-augmented OT Anomaly Detection)
- **MTTR hard stop ≤ 1 hour** (SMED recovery rig + IR Automation Agent)
- **MTTR OT compromise ≤ 8 hours** (forensics + clean-state restoration)
- **FMEA RPN reduction ≥ 80%** across top 10 modes
- **Patch compliance ≥ 99%** in maintenance windows

The 4 AI agents are the structural answer to "how do you hold Z ≥ 6.0 when human SOC capacity is finite."

## Data-Access Governance compliance

All components respect the §3.5 Data-Blind Protocol:

- **AI agents query ONLY the anonymised data lake** (never raw data)
- **GBs query ONLY via the locked, read-only query interface**
- **Anonymisation pipeline is CISO-controlled**, not GB-controlled
- **Every agent action is logged and audit-reviewable**
- **CISO retains kill-switch authority on every agent**

The agents operate in a "CISO-mediated trust boundary" — they can be powerful precisely because their access is bounded and auditable.

## Deployment phases

The implementation is staged to match the 12-week engagement:

| Weeks | Component deployed | Track |
|---|---|---|
| 1–3 | Anonymised data lake (interface only; pipeline is CISO-team-owned) | Track B |
| 4–5 | Baseline measurement + capability report | Track B |
| 6–7 | Poka-Yoke design + control-point spec | All tracks |
| 8–10 | **All reference implementations deployed**: AI agents, Poka-Yoke enforcers, SMED rig, dashboard, SPC charts, FMEA control plan, Kaizen router, Standard Work automation | All tracks |
| 11–12 | Standard Work embedded; SOPs laminated; AI agents handed off to IT Security for sustained operation | All tracks |
| Week 13+ | Continuation phase (Standard Work + Kaizen + cross-site replication) | Track Leads + MBB |

## Quality and test discipline

- **All Python code:** type hints, docstrings, error handling, structured logging, ≤ 200 lines per module
- **All AI agents:** kill-switch accessible, action-logged, idempotent operations
- **All Poka-Yoke enforcers:** fail-closed (deny by default on any error)
- **All data-lake queries:** bounded results, audit logged, time-limited
- **Test coverage target:** ≥ 80% line coverage, 100% on the safety-critical components (Poka-Yoke, SMED, IR Automation)

## Naming conventions

- Python files: `snake_case.py`
- Config: `config.yaml` (never `.json` — comments matter)
- Tests: `test_<module>.py` mirroring the module
- Documentation: `UPPERCASE.md` (architecture, data-flow, etc.)
- No timestamps in filenames (per project convention)
- No date-captured in YAML frontmatter (per project convention)

## How to use this folder

1. **Track A (Architecture, 6 GBs):** Read `00-specifications/poka-yoke/` first; adapt `01-reference-implementations/poka-yoke/` to the actual OT environment; deploy in Weeks 8–10
2. **Track B (Data & Metrics, 7 GBs):** Read `00-specifications/data-lake/` and `01-reference-implementations/data-lake/`; collaborate with the CISO team on the anonymisation pipeline; deploy SPC charts in Weeks 11–12
3. **Track C (Automation, 6 GBs):** Read `00-specifications/ai-agents/` and `01-reference-implementations/ai-agents/`; build, test, and integrate the 4 AI agents; deploy SMED rig in Weeks 8–10
4. **MBB (Olivia):** Review all 13 Kaizen triggers (`01-reference-implementations/kaizen/`); chair the tollgate reviews; sign off on each component at G2, G3, G4, G5

## Constraints and what NOT to do

- **Do not** modify the anonymisation pipeline — that is CISO-team-only
- **Do not** expose raw data to AI agents — all access is via the anonymised data lake
- **Do not** deploy without kill-switch testing — every agent must be killable
- **Do not** relax the data-classification rules (ALLOWED / RESTRICTED / PROHIBITED) for any reason
- **Do not** skip the Standard Work or Kaizen trigger catalog — they are the entropy defence for the engagement itself

## Engagement context

- **Project:** Cyber Resilience Project Charter for Global EV Cell Manufacturing — Phase 1 (Define)
- **Engagement-level target:** Z ≥ 6.0 (theoretical Six Sigma)
- **Exposure band:** $20M–$180M+ per year per department (5 exposure classes)
- **5-site enterprise protected value:** $25M–$225M+ per year (conservative capture M=25%)
- **Team:** 19 Green Belts × 10% = 1.9 FTE + 1.0 FTE MBB
- **Duration:** 12 weeks, 5 tollgates (G1 Define → G5 Control)
- **CISO:** Executive Sponsor; sole signatory on every tollgate

This implementation folder is the Phase 4 (Improve) deliverable. The Phase 1 (Define) charter is in the parent `deliverables/` folder and the public URLs are:
- Full charter: https://87x1siaib1okk.space.minimax.io
- Standalone CISO dashboard: https://6z9fkk0oehsun.space.minimax.io
