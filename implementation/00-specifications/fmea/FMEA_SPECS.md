# Cyber-FMEA Control Plan Specifications

The Cyber-FMEA (Failure Mode and Effects Analysis) is the binding risk model for the engagement. The control plan is the operational document that drives Standard Work, Kaizen triggers, and continuous improvement.

## Charter reference

§4.4 Cyber-FMEA Methodology.

## Scoring methodology

### Severity (S) — 1-10

- **10 (Existential):** Loss of life, regulatory shutdown, existential business impact. Examples: thermal runaway, fire, EU PLD strict liability event, battery fire
- **9 (Critical):** Major product recall, safety incident risk, regulatory fine at ceiling. Examples: critical product recall, NIS2 ceiling fine
- **8 (Very High):** Significant customer impact, contractual breach with major OEM, significant yield loss
- **7 (High):** Major OEE/yield impact, multiple-line impact
- **6 (Moderate-High):** Single-line significant impact
- **5 (Moderate):** Recoverable single-line impact
- **1-4 (Low to Minor):** Localised, recoverable impact

### Occurrence (O) — 1-10

Industry-anchored frequency:

- **10:** > 1 in 6 months
- **9:** 1 in 6-12 months
- **8:** 1 in 1-2 years
- **7:** 1 in 2-3 years
- **6:** 1 in 3-5 years
- **5:** 1 in 5-7 years
- **4:** 1 in 7-10 years
- **3:** 1 in 10-15 years
- **2:** 1 in 15-30 years
- **1:** < 1 in 30 years

### Detection (D) — 1-10

Difficulty of detecting the failure mode before it causes harm:

- **10 (Very Hard):** No halt event, no inspection failure. The failure is invisible until it manifests in the field. **All silent corruption modes.**
- **9:** Detection requires specialised tooling; high false negative rate
- **8:** Detection requires correlation across multiple signals
- **7:** Detection requires specific monitoring tooling
- **6:** Detection requires routine inspection
- **5:** Detected by standard SIEM/SOC monitoring
- **1-4:** Detected by basic checks; high detection rate

### RPN calculation

```
RPN = S × O × D
```

### Capability targets (Six Sigma-aligned)

- **Silent corruption modes (SC):** S = 10 (existential), D = 7-9 (very hard to detect), RPN up to 540
- **Hard stop modes:** S = 8-10, D = 5-8, RPN up to 350
- **RPN reduction target:** ≥ 80% across top 10 modes (Six Sigma-aligned; was 50% for 4.5σ)

## Top 12 FMEA modes (recalibrated)

| # | Process Step | Failure Mode | S | O | D | RPN | SC | Primary Exposure Class |
|---|---|---|---|---|---|---|---|---|
| 1 | Formation & Aging (SC) | Aging cycle manipulation | **10** | 6 | 9 | **540** | ✓ | E_silent_corruption |
| 2 | Electrode Coating (SC) | Coating thickness tampering | **10** | 7 | 7 | **490** | ✓ | E_silent_corruption |
| 3 | Slurry Mixing (SC) | Sensor data spoofing | **10** | 6 | 8 | **480** | ✓ | E_silent_corruption |
| 4 | Grading & Sorting (SC) | Capacity test data tampering | **10** | 5 | 9 | **450** | ✓ | E_silent_corruption |
| 5 | Electrode Coating (SC) | Vision system data spoofing | **10** | 5 | 9 | **450** | ✓ | E_silent_corruption |
| 6 | Cell Assembly (SC) | Stacking parameter tampering | **10** | 5 | 8 | **400** | ✓ | E_silent_corruption |
| 7 | Grading & Sorting (SC) | IR test data manipulation | **10** | 4 | 9 | **360** | ✓ | E_silent_corruption |
| 8 | Formation & Aging | Charging profile tampering | 10 | 5 | 7 | **350** | | E_safety |
| 9 | Slurry Mixing | Ransomware locks Industrial PC | 8 | 7 | 6 | **336** | | E_downtime |
| 10 | Electrolyte Injection | Dosing volume tampering | 10 | 4 | 8 | **320** | | E_safety |
| 11 | Slurry Mixing | Batch tracking malware | 7 | 5 | 7 | **245** | | E_downtime |
| 12 | Cell Assembly | Authentication bypass | 9 | 3 | 7 | **189** | | E_downtime |

**Observations:**
- 7 of 12 are silent corruption (SC); all at S = 10
- Top 5 RPN modes (≥ 450) are all SC
- SC detection is the binding constraint (D = 7-9) — AI-augmented Layer 3 is structurally necessary
- 3 of 12 are safety-class (E_safety); 1 of 12 is hard-downtime (E_downtime + E_safety)

## FMEA-to-exposure-class mapping

| FMEA mode range | Primary exposure class | Secondary |
|---|---|---|
| #1-7 (SC modes) | E_silent_corruption | E_regulatory (recall) |
| #8, #10 (safety-critical) | E_safety | E_downtime |
| #9, #11 (ransomware / MES) | E_downtime | E_regulatory (NIS2) |
| #12 (auth bypass) | E_downtime | E_silent_corruption |

## FMEA-to-Poka-Yoke mapping

| Poka-Yoke principle | FMEA modes addressed |
|---|---|
| #1 Hard-coded network isolation | #7, #8, #10 (safety-critical OT) |
| #2 One-way data diodes | #8, #10 (safety-critical paths) |
| #3 Cryptographic recipe signing | #1-7 (all SC modes — parameter integrity) |
| #4 Vendor remote access broker | #9, #11, #12 (vendor-mediated vectors) |
| #5 Parameter drift interlocks | #1-7 (all SC modes — runtime detection) |

**SC modes (#1-7) are protected by 3+ Poka-Yoke principles each. Defence in depth.**

## FMEA control plan

The control plan is the operational document. For each FMEA mode, it specifies:

### Template

```
FMEA Mode #: [mode number]
Process Step: [process step]
Failure Mode: [description]
S: [1-10]  O: [1-10]  D: [1-10]  RPN: [S × O × D]
High-Risk Root Cause: [description]

Controls (Poka-Yoke + AI agents + SMED):
  - Detection: [which agent/control detects this]
  - Prevention: [which control prevents this]
  - Response: [which SMED playbook / IR action responds to this]

Monitoring:
  - SPC chart: [yes/no, which chart]
  - Drill cadence: [weekly/monthly/quarterly]
  - Alert threshold: [when to escalate]

Kaizen Triggers:
  - [which of the 13 triggers applies]
  - [A3 owner / escalation tier]

Last Refresh: [date]
Next Refresh: [date + 3 months]
```

### Example: FMEA Mode #1 (Formation & Aging aging cycle manipulation)

```
FMEA Mode #: 1
Process Step: Formation & Aging
Failure Mode: Aging cycle manipulation → accelerated cell degradation → field failure → recall
S: 10  O: 6  D: 9  RPN: 540

Controls:
  - Detection: OT Anomaly Detection Agent (parameter drift vs signed recipe)
  - Prevention: Poka-Yoke #3 (cryptographic recipe signing — recipes can't be modified without HSM key)
  - Prevention: Poka-Yoke #5 (parameter drift interlock — auto-isolates line at >5% drift)
  - Response: IR Automation Agent → "formation_charging_tampering" SMED playbook
  - Response: SMED recovery (pre-staged golden image, restore rig, ≤ 1 hour MTTR)

Monitoring:
  - SPC chart: yes (I-MR chart on aging cycle deviation)
  - Drill cadence: monthly (Track C standard work)
  - Alert threshold: any parameter drift > 1% triggers Tier 1; > 5% triggers Tier 2 + auto-isolate

Kaizen Triggers: #1 (SPC UCL breach), #2 (MTTR breach), #8 (AI agent drift), #11-13 (structural)

Last Refresh: 2026-08-15 (Q3)
Next Refresh: 2026-11-15 (Q4)
```

## FMEA refresh schedule

- **Quarterly (every 3 months):** Mandatory refresh for all 12 modes
  - Re-evaluate S, O, D scores
  - Add new failure modes if applicable (new equipment, new firmware, new line)
  - Update root cause analysis
  - Review control plan
  - Trigger: `Kaizen Trigger #4 (regulatory change)` accelerates if needed
- **Off-cycle triggers:**
  - New equipment deployment (Kaizen Trigger #3)
  - New firmware release (refresh S/O/D for affected modes)
  - Major industry event (Kaizen Trigger #5)
  - Audit finding (Kaizen Trigger #7)
  - Process change (Kaizen Trigger #9)
  - Tooling change (Kaizen Trigger #10)
  - Supply chain / M&A / IP licensing (Kaizen Triggers #11-13)

## FMEA control plan database (logical schema)

```sql
CREATE TABLE fmea_control_plan (
    mode_id           INT PRIMARY KEY,
    detection_control VARCHAR(256),
    prevention_controls JSON,                  -- list of Poka-Yoke + agents
    response_playbook_id VARCHAR(64),
    spc_chart_id      VARCHAR(64),
    drill_cadence     VARCHAR(32),              -- weekly | monthly | quarterly
    alert_threshold   JSON,                     -- {tier_1: ..., tier_2: ..., tier_3: ...}
    kaizen_triggers   JSON,                     -- list of trigger IDs
    last_refresh      TIMESTAMP NOT NULL,
    next_refresh      TIMESTAMP NOT NULL,
    INDEX idx_next_refresh (next_refresh)
);
```

## Reference implementation

- Schema lives in the anonymised data lake (read-only view for GBs)
- Control plan document maintained by MBB + Track Leads
- Quarterly FMEA refresh executed as Standard Work routine

## Deployment

- MBB owns the FMEA control plan document
- Track Leads contribute to the quarterly FMEA refresh
- CISO reviews at bi-annual audit
- FMEA deltas trigger control plan updates (via Track C AI agent or human review)

## Six Sigma alignment

The FMEA control plan supports the engagement-level target of Z ≥ 6.0:

- 7 of 12 modes (the SC class) are protected by 3+ Poka-Yoke principles
- Detection target: MTTD ≤ 10 min for novel SC modes (AI-augmented)
- Response target: MTTR ≤ 1 hour for hard stops, ≤ 30 min for safety-critical
- FMEA RPN reduction target: ≥ 80% across top 10 modes (Six Sigma-aligned)

**Target:** FMEA control plan is the binding document for sustained operation. Quarterly refresh keeps it current; off-cycle triggers keep it responsive to change.
