# Architecture — Cyber Resilience Implementation

## System overview

```
┌────────────────────────────────────────────────────────────────────────────┐
│                  CORPORATE IT  (RESTRICTED to CISO team)                   │
│                                                                              │
│   ┌────────────┐    ┌─────────────────┐    ┌──────────────────────┐        │
│   │ OT/IT raw  │ →  │ Anonymisation   │ →  │ Anonymised data lake │        │
│   │ data       │    │ pipeline (CISO) │    │ (ALLOWED outputs)    │        │
│   └────────────┘    └─────────────────┘    └──────────┬───────────┘        │
│                                                      │                    │
└──────────────────────────────────────────────────────┼────────────────────┘
                                                       │ read-only query
                                                       ▼
┌────────────────────────────────────────────────────────────────────────────┐
│           DATA-BLIND TRUST BOUNDARY  (#3.5 of the charter)                 │
│                                                                              │
│   ┌────────────────────────────────────────────────────────────────────┐   │
│   │              19 GREEN BELTS × 10% = 1.9 FTE                        │   │
│   │                                                                     │   │
│   │   Track A (6)              Track B (7)              Track C (6)    │   │
│   │   Architecture             Data & Metrics          Automation    │   │
│   │   ├ Poka-Yoke              ├ Query interface       ├ AI agents   │   │
│   │   ├ DMZ                    ├ SPC charts             ├ SMED rig    │   │
│   │   ├ Vendor broker          ├ FMEA control plan      ├ IR auto     │   │
│   │   └ Air-gap                └ Capability report      └ Recovery    │   │
│   └────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│                       ▲ kill-switch (CISO authority)                          │
│                       │ audit log (every agent action)                       │
└────────────────────────────────────────────────────────────────────────────┘
```

## Component responsibilities

### Track A — Architecture (6 GBs)
- **Cyber Poka-Yoke enforcement** (`poka-yoke/`): 5 structural principles
  1. Hard-coded network isolation at PLC firmware level
  2. One-way data diodes on safety-critical paths
  3. Cryptographic recipe signing
  4. Vendor remote-access broker
  5. Parameter drift interlocks with auto-isolation
- **DMZ and segmentation:** IT/OT air gap, Purdue Model compliance
- **Vendor remote-access broker:** cryptographic handshake, session recording
- **Digital 5C infrastructure:** legacy protocol decommission, asset inventory, code standards

### Track B — Data & Metrics (7 GBs)
- **Anonymised data lake** (interface only — pipeline is CISO-team-owned): read-only query interface
- **SPC charts** (`dashboard/spc/`): p-chart, I-MR chart, u-chart, Cpk trend
- **FMEA control plan** (`fmea/`): top 12 modes + quarterly refresh
- **Capability reporting:** Z-score, Cpk, MTTD/MTTR distributions
- **Standard Work automation** (`standard-work/`): weekly/monthly/quarterly routines

### Track C — Automation (6 GBs)
- **4 AI agents** (`ai-agents/`):
  1. SOC Triage Agent (MTTD ≤ 2 min for known signatures)
  2. OT Anomaly Detection Agent (MTTD ≤ 10 min for novel anomalies)
  3. IR Automation Agent (MTTR ≤ 1 hour for hard stops)
  4. Threat Intel Correlation Agent (preventive)
- **SMED recovery rig** (`smed/`): pre-staged backups, immutable offline hot-swap, recovery automation
- **Cryptographic signing infrastructure** (interfaces with Track A)
- **Kaizen router** (`kaizen/`): 13 triggers, A3 generator

### MBB (Olivia)
- **Kaizen review chair:** all 13 triggers routed through MBB at appropriate tier
- **Tollgate presentation:** sole presenter to CISO at G1–G5
- **Track coordination:** resolves cross-track dependencies at Tier 2
- **Continuation governance:** quarterly maturity score recalculation

### CISO (Executive Sponsor)
- **Risk appetite setting:** defines what residual risk is acceptable
- **Confidentiality protocol ownership:** owns the data-access governance
- **Tollgate sign-off:** sole signatory on G1–G5
- **AI agent kill-switch authority:** can disable any agent, any time
- **Incident notification:** real-time alerts on confirmed cyber events

## Data flow (anonymised)

```
[ OT/IT raw data ]  →  [ CISO anonymisation pipeline ]  →  [ Anonymised data lake ]
                                                                       │
                                                                       ▼
                                                          [ GB query interface ]
                                                                       │
                                                                       ▼
                                              [ 4 AI agents + SPC + FMEA + dashboard ]
                                                                       │
                                                                       ▼
                                              [ Action logging → audit trail → CISO ]
```

The anonymisation pipeline is CISO-team-owned. GBs and AI agents NEVER touch raw data. Every query is logged, every agent action is auditable, every data access is bounded.

## Trust boundary enforcement

- **Network:** DMZ, one-way data diodes, vendor broker, air-gap on safety paths
- **Identity:** MFA, RBAC, time-bounded credentials, cryptographic handshake for vendors
- **Audit:** quarterly third-party audit, monthly access review by CISO team
- **Breach response:** 1h access revocation, 24h forensic review, engagement pause pending CISO

## Six Sigma design

Every component targets **Cpk ≥ 2.0** (Z ≥ 6.0):

- AI agents are bounded, idempotent, killable, audited
- Poka-Yoke enforcers are fail-closed (deny by default on any error)
- SMED rig is pre-staged, tested, recoverable
- Data lake queries are bounded, time-limited, audit-logged
- SPC charts have explicit control limits and escalation rules

The capability indices (Cpk, Z) are the binding MBB metrics. Time values (MTTD, MTTR) are operational expressions validated in the Measure phase (Tollgate G2).

## Deployment topology

- **AI agents:** containerised, deployed in the OT edge network, communication via the anonymised data lake
- **Poka-Yoke enforcers:** run on the OT network, low-latency, fail-closed
- **SMED rig:** air-gapped for backup validation, networked only for orchestration
- **SPC charts:** deployed in the corporate BI environment, fed by the anonymised data lake
- **Executive Dashboard:** accessible to CISO and authorised stakeholders, fed by the SPC layer
- **Standard Work / Kaizen:** web-based tools, accessible to all 19 GBs

## Failure modes and resilience

| Failure | Response | Time-to-recovery |
|---|---|---|
| AI agent crash | CISO kill-switch; manual fallback to human SOC | ≤ 5 min |
| Poka-Yoke false positive | Auto-isolate; human review within 30 min | ≤ 1 hour |
| Poka-Yoke false negative (missed attack) | Anomaly detection + threat intel correlation catches within MTTD | ≤ 10 min |
| SMED rig corruption | Immutable offline backup; restore from validated golden image | ≤ 1 hour |
| Data lake unavailability | CISO team fallback to manual anonymised queries | ≤ 4 hours |
| Tooling change (new SIEM, new PLC vendor) | Kaizen trigger #10; FMEA refresh; control plan update | ≤ 5 BD |
| CISO unavailable | Delegate authorised; engagement quality depends on delegate authority | ≤ 24 hours |

## Six Sigma-aligned operational targets (recap)

| Sub-process | Capability | Operational |
|---|---|---|
| Detection — known signatures | Cpk ≥ 2.0, Z ≥ 6.0 | MTTD ≤ 2 min |
| Detection — novel OT anomalies | Cpk ≥ 2.0, Z ≥ 6.0 | MTTD ≤ 10 min |
| Response — hard stop | Cpk ≥ 2.0, Z ≥ 6.0 | MTTR ≤ 1 hour |
| Response — OT compromise | Cpk ≥ 2.0, Z ≥ 6.0 | MTTR ≤ 8 hours |
| Prevention (patch) | Cpk ≥ 2.0, Z ≥ 6.0 | ≥ 99% in maintenance windows |
| FMEA RPN reduction | — | ≥ 80% across top 10 modes |
