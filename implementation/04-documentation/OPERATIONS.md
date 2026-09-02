# Operations — Cyber Resilience Implementation

## Operating model

The engagement operates on a 4-tier model that maps to the §3.4 escalation matrix and the §7 governance cycle.

### Tier 1 — Track Lead (24h SLA)

**Owner:** Track Lead (Track A, B, or C)
**Scope:** Track-internal issues
**Examples:**
- A GB has a tooling question
- A track-internal code review
- A patch compliance gap on a specific line
- A test failure during deployment
**Authority:** Track Lead decides; can escalate to Tier 2 if cross-track

### Tier 2 — MBB (24h SLA)

**Owner:** MBB (Olivia)
**Scope:** Cross-track issues
**Examples:**
- Track A's segmentation impacts Track C's Poka-Yoke enforcement
- Track B's data lake is blocking Track A's audits
- Two tracks disagree on a control plan change
**Authority:** MBB decides; can escalate to Tier 3 if budget/scope/risk

### Tier 3 — CISO + MBB (48h SLA)

**Owner:** CISO + MBB
**Scope:** Budget, scope, risk-appetite deviation
**Examples:**
- Tooling purchase > $50K
- Scope addition (new failure mode or new system)
- Risk-appetite change
- Tier 2 escalation that needs policy decision
**Authority:** CISO decides (budget, risk); MBB decides (scope re-baseline)

### Tier 4 — Executive Committee (5 BD SLA)

**Owner:** Executive Committee (via CISO)
**Scope:** Strategic, regulatory, external-party
**Examples:**
- OEM contractual breach disclosure
- NIS2 disclosure trigger
- M&A or IP licensing event
- Confirmed Tier 3 escalation involving regulatory or external exposure
**Authority:** Executive Committee

### Real-Time Incident (no SLA — immediate)

**Owner:** MBB + IT Security
**Scope:** Confirmed cyber event on a protected line
**Authority:** MBB operational; CISO strategic (notified within 15 min)

## Standard Work (§6.2 of the charter)

The 19 Green Belts execute the following routines at 10% weekly capacity allocation. Every routine has explicit cadence, owner, activity, deliverable, and escalation if missed.

### Weekly (1.5-2 hours per GB)

| Routine | Owner | Activity | Deliverable | Time | Escalation if missed |
|---|---|---|---|---|---|
| SPC chart review | Track B GBs | Review all deployed SPC charts; identify any points outside UCL | Weekly SPC log entry; UCL breach investigation if applicable | 30 min | Tier 1 to Track Lead within 24h |
| 5-Why on UCL breach | Track B GB (assigned) | If UCL breach detected: lead 5-Why analysis with Track Lead | 5-Why A3 document | 1-2 h | Tier 2 to MBB if root cause is structural |
| Access log review | Track A GBs | Review anonymised access logs; flag any anomalous query pattern | Weekly access review note | 30 min | Tier 1 to Track Lead; Tier 4 if data-access breach suspected |
| AI agent log review | Track C GBs | Review AI agent decision logs; flag any agent decision outside training distribution | Weekly agent log review; kill-switch trigger if needed | 30 min | Tier 2 to MBB if agent drift detected |
| Track Lead weekly sync | All GBs + Track Leads | 30-min standup: progress, blockers, anomalies | Meeting notes in engagement log | 30 min/week/GB | None (mandatory) |

### Monthly (4-8 hours per GB)

| Routine | Owner | Activity | Deliverable | Time | Escalation if missed |
|---|---|---|---|---|---|
| Cyber-attack drill | Track C GBs (rotating) | Execute simulated ransomware / parameter-tampering attack on isolated test bench | Drill report: MTTD / MTTR achieved vs target | 4 h | Tier 2 to MBB; control plan review if MTTR breach |
| SMED recovery verification | Track C GBs (rotating) | Validate SMED recovery time remains < 1h target for hard stop | SMED validation log | 2 h | Tier 2 if MTTR exceeds 1h |
| Patch compliance review | Track A GBs | Review patch compliance dashboard; flag any assets below 99% | Patch compliance report | 2 h | Tier 2 to MBB if compliance < 95% |
| Vendor remote-access review | Track A GBs | Review vendor remote-access logs; flag anomalous sessions | Vendor access audit log | 1 h | Tier 4 if vendor access breach |
| AI agent performance review | Track C GBs | Review AI agent KPIs (precision, recall, false positive rate) | Agent performance report | 2 h | Tier 2 if any agent performance degrades > 10% from baseline |
| Cross-track coordination | MBB + Track Leads | 60-min monthly review: cross-track dependencies, risk register, resource allocation | Meeting notes; risk register update | 1 h/lead | None (mandatory) |

### Quarterly (16-24 hours per GB; Track Lead-led)

| Routine | Owner | Activity | Deliverable | Time | Escalation if missed |
|---|---|---|---|---|---|
| **FMEA refresh** | All tracks | Review FMEA against new equipment, firmware updates, line software changes; recalculate RPN | Updated FMEA matrix; new failure modes identified | 8 h/GB | Tier 2 to MBB if RPN materially shifts |
| **Control plan review** | MBB + Track Leads | Review control plan effectiveness; update SPC chart logic if needed | Updated control plan | 4 h/lead | Tier 3 to CISO if control plan structurally inadequate |
| **Maturity score recalculation** | MBB | Recalculate maturity score (§6.4); identify capability gaps | Updated maturity score; gap remediation plan | 4 h/MBB | Tier 3 to CISO if maturity score drops |
| **Cross-site knowledge transfer** | MBB + GBs (rotating) | Transfer lessons learned, control plan updates, FMEA changes to other sites | Knowledge transfer log; site adoption confirmation | 8 h/GB | Tier 3 to CISO if site adoption fails |
| **Threat landscape review** | Track C GBs + IT Security | Review emerging threats, APT campaigns, regulatory changes | Threat landscape brief; control plan update if needed | 4 h/GB | Tier 3 if new high-RPN failure mode identified |
| **AI agent retraining** | Track C GBs | Retrain AI agents on updated baseline; validate performance post-retraining | Retrained agents; performance report | 8 h/GB | Tier 2 if retraining fails to recover baseline performance |
| **Tabletop exercise** | All tracks + IT Security + Operations | Cross-functional tabletop: simulated OT compromise, IR cycle execution, lessons learned | Tabletop A3; control plan updates | 4 h/GB | Tier 2 to MBB; CISO briefed at next bi-weekly |

### Annual (40-80 hours per GB; Track Lead + MBB)

| Routine | Owner | Activity | Deliverable | Time | Escalation if missed |
|---|---|---|---|---|---|
| **Full control plan audit** | MBB + Track Leads + external | Comprehensive audit of all controls, SPC charts, Poka-Yoke enforcement, AI agent governance | Audit report; remediation plan | 40 h/GB + 80 h/lead | Tier 3 to CISO; CISO + executive committee if material gaps |
| **Third-party security assessment** | External assessor | Independent security assessment (red team, penetration test, configuration review) | Third-party assessment report | 40 h coordination | Tier 3 to CISO; engagement scope review |
| **Regulatory compliance audit** | MBB + Legal/Compliance | NIS2, IEC 62443, OEM cyber attestation audit | Compliance attestation | 20 h/MBB | Tier 4 if any non-compliance finding |
| **Bi-annual CISO audit** | CISO + MBB | Joint audit of engagement performance, control plan, maturity score, COPQ protected value | CISO audit report | 8 h/MBB + 4 h/CISO | Executive committee briefing if material gaps |
| **Insurance review** | MBB + Legal/Compliance + Finance | Review cyber insurance coverage against current exposure band | Insurance review note | 8 h/MBB | Tier 3 if coverage materially inadequate |
| **Strategic threat landscape review** | MBB + CISO + IT Security | Forward-looking review of threat landscape, regulatory direction, technology shifts | Strategic threat brief; engagement re-scoping if needed | 16 h/MBB | CISO decision on engagement continuation/scope |
| **Maturity score external validation** | External assessor | Third-party validation of maturity score calculation and evidence | External validation report | 16 h coordination | Tier 3 if external validation materially diverges from internal score |

## AI agent operations

### Kill switch (CISO authority)

Every agent has a kill switch. CISO can disable any agent, any time, by flipping a config flag.

**CISO escalation path:**
1. CISO decides to kill an agent (e.g., during an incident, for maintenance, or for policy reasons)
2. CISO or delegate writes `{"enabled": false}` to the agent's kill switch config file
3. The agent stops accepting new actions; in-flight actions complete or are paused
4. The kill event is logged to the audit trail
5. To revive, CISO writes `{"enabled": true}` with a reason; revival is also logged

**Agent health monitoring:**
- Each agent exposes a `health()` method returning enabled state, action count, last action timestamp, FMEA modes addressed
- Health is queried by the executive dashboard (Tile 5 — Kaizen Activity)
- Sustained health degradation (e.g., enabled=False for >24h without planned maintenance) triggers Tier 2 escalation

### AI agent action review

Every AI agent action is logged. The audit log includes:
- Timestamp
- Agent ID
- Action type (e.g., "alert_processed", "data_lake_query", "line_segment_isolated", "playbook_executed")
- Details (alert ID, classification, routing, severity, confidence, etc.)

Track C Lead reviews the AI agent logs weekly as part of Standard Work. The review looks for:
- Agent decisions that were overridden by humans (indicates model drift)
- Agent actions that triggered Tier 2+ escalation (indicates high-severity events)
- Kill switch events (indicates policy interventions)
- Performance degradation (precision, recall, false positive rate trends)

If patterns indicate drift, Track C Lead triggers AI agent retraining (quarterly routine or off-cycle if needed).

## Control plan execution

The control plan (§4.6.3 of the charter) is the binding document for sustained operation. It defines:

- **Automated triggers:** if any SPC chart breaches UCL, the system automatically isolates the affected line segment before lateral spread
- **Standard work:** every Green Belt follows the weekly / monthly / quarterly / annual routines
- **Escalation discipline:** every anomaly is logged; UCL breaches trigger Tier 1/2 escalation per §3.4
- **Audit cadence:** bi-annual CISO audit, annual third-party audit
- **FMEA refresh:** quarterly FMEA refresh to account for new equipment, firmware, line software

## Operational targets (Six Sigma-aligned)

Every operational target maps to a §1.4.1 sub-process capability target:

| Sub-process | Operational | Measured by |
|---|---|---|
| Detection — known signatures | MTTD ≤ 2 min | SOC Triage Agent metrics |
| Detection — novel OT anomalies | MTTD ≤ 10 min | OT Anomaly Detection Agent metrics |
| Response — hard stop | MTTR ≤ 1 hour | IR Automation Agent + SMED metrics |
| Response — OT compromise | MTTR ≤ 8 hours | IR Automation + Forensics metrics |
| Prevention (patch) | ≥ 99% in maintenance windows | Track A patch compliance dashboard |
| FMEA RPN reduction | ≥ 80% across top 10 modes | Quarterly FMEA refresh |

## Incident playbook execution

When a real-time incident is confirmed:

1. **SOC Triage or OT Anomaly detects** and routes to IR Automation
2. **IR Automation selects playbook** (e.g., "ransomware_industrial_pc")
3. **CISO authorisation check** — playbook may be pre-authorised (CISO standing approval) or per-incident approval required
4. **Playbook executes** — each step is logged to audit trail
5. **Line segment isolated** (via Poka-Yoke enforcement, fail-closed)
6. **Forensic state snapshot** (to immutable offline backup)
7. **CISO notified** (within 15 min for hard stop, within 1 min for safety)
8. **SMED recovery** — pre-staged assets used to restore clean state
9. **Verification** — clean state validated, recipes re-verified
10. **Line resumes production** — with monitored operation for 24h

## On-call rotation

For real-time incidents, the engagement maintains an on-call rotation:

- **Primary on-call:** Track Lead (rotating weekly)
- **Secondary on-call:** MBB (always available)
- **Tertiary on-call:** CISO (15 min response SLA for hard stops, 1 min for safety)

The on-call rotation is maintained by the MBB and reviewed at each bi-weekly briefing.

## Tools and infrastructure

The engagement uses the following tools (in production):

- **CISO data lake:** PostgreSQL or similar, managed by CISO team
- **Anonymisation pipeline:** Apache Airflow or similar, managed by CISO team
- **AI agents:** Python services deployed as systemd services (or K8s pods in larger deployments)
- **Poka-Yoke enforcement:** Python + PLC firmware integration
- **SMED recovery:** Python orchestrator + physical hardware (air-gapped restore rigs)
- **SPC charts:** Plotly, embedded in the Executive Dashboard
- **Executive Dashboard:** Streamlit or similar, fed by the SPC layer
- **Audit log:** Append-only JSONL, with cryptographic chaining
- **Standard Work / Kaizen:** Web-based tools, accessible to all 19 GBs

All tools are designed to be replaced/swapped without changing the engagement's data flow or governance model.

## Continuous improvement (Kaizen)

13 Kaizen triggers (§6.3 of the charter) initiate immediate response:

**Routine (Tier 1/2):**
1. SPC UCL breach
2. MTTR breach in drill
3. New asset ingress (PLC / line tool)
4. Regulatory change (NIS2 amendment, OEM attestation update)
5. Industry peer event (peer manufacturer breach) — auto-Tier 2 within 48h
6. Personnel change (key GB departure)
7. Audit finding (internal or external)
8. AI agent drift (performance degradation)
9. Significant process change (new chemistry, new line)
10. Tooling change (new SIEM, new PLC vendor)

**Structural (Tier 3, may require engagement re-scope):**
11. Supply chain change (vendor swap, contract renegotiation, new tier-2 supplier)
12. M&A activity (acquisition, divestiture, JV)
13. IP licensing event (new partner, licensee, cross-licensing)

All 13 triggers → A3 within 5 business days. Structural triggers escalate to CISO immediately.

## Metrics reporting cadence

| Metric | Cadence | Audience |
|---|---|---|
| Executive Dashboard (8 tiles) | Real-time (auto-refresh) | CISO + MBB |
| Bi-weekly briefing | Every 2 weeks | CISO + MBB + Track Leads (as needed) |
| Monthly operational report | Monthly | Track Leads + MBB |
| Quarterly FMEA + maturity | Quarterly | CISO + executive committee |
| Bi-annual audit | Every 6 months | CISO + Operations + IT Security + Legal |
| Annual strategic review | Annually | CISO + executive committee + external assessor |

## What this means for engagement sustainability

The 12-week push is the **initial structural implementation**. The continuation phase (Week 13+) is what makes the engagement **operational infrastructure** rather than a one-time project. The Standard Work, Kaizen triggers, and maturity scoring are the structural protection against project degradation — exactly the entropy defence the OSI whitepaper's Layer 4 was designed to provide.
