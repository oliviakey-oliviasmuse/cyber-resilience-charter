# Data Flow — Cyber Resilience Implementation

## End-to-end data flow

The engagement operates within a strict data-blind architecture (#3.5 of the charter). The data flow has four trust zones:

```
┌──────────────────────────────────────────────────────────────────────────┐
│ ZONE 1: OT/IT RAW DATA  (CISO-team access only)                          │
│                                                                           │
│   - PLCs, SCADA, MES, SIEM, firewalls, identity providers                 │
│   - Contains IP addresses, hostnames, MAC addresses, raw logs, credentials│
│   - AI agents NEVER see this zone                                       │
│   - GBs NEVER see this zone                                             │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │ (only CISO anonymisation pipeline crosses this boundary)
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ ZONE 2: CISO ANONYMISATION PIPELINE  (CISO-team owned)                   │
│                                                                           │
│   - Strips PII, IP addresses, hostnames, vendor-specific identifiers       │
│   - Produces only ALLOWED outputs (#3.5):                                │
│     - Time deltas (MTTD, MTTR, cycle time)                                │
│     - Compliance % (patch, MFA, encryption)                              │
│     - Defect rates, traffic volumes, event counts                        │
│     - Capability indices (Cpk, Z-score, DPMO)                           │
│     - Anonymised process parameters (with signed baselines)              │
│   - Pipeline integrity audited quarterly by third party                  │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │ (only ALLOWED outputs cross this boundary)
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ ZONE 3: ANONYMISED DATA LAKE  (GB and AI agent access)                   │
│                                                                           │
│   - Read-only query interface for GBs (Python `AnonymisedDataLake`)       │
│   - AI agents query via the same interface (audited)                      │
│   - All queries bounded (max_rows=10000) and time-limited (30s default)   │
│   - Every query logged to the audit trail                                │
│   - Storage: PostgreSQL or similar (in production)                       │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
   │ 4 AI agents  │   │ 19 GBs       │   │ SPC charts   │
   │ - SOC Triage │   │ - Track A/B/C│   │ - p-chart     │
   │ - OT Anomaly │   │              │   │ - I-MR chart  │
   │ - IR Auto    │   │              │   │ - u-chart     │
   │ - Threat Intel│   │              │   │ - Cpk trend   │
   └──────────────┘   └──────────────┘   └──────────────┘
            │                  │                  │
            └──────────────────┼──────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ ZONE 4: CONTROL PLANE  (action output, not data)                         │
│                                                                           │
│   - Poka-Yoke enforcement (isolation signals to PLCs)                     │
│   - SMED recovery orchestrator (recovery actions)                       │
│   - Executive Dashboard (visualisations, no raw data)                   │
│   - CISO notification (15 min for hard stops, 1 min for safety)          │
│   - Audit trail (every action, every query, every decision)              │
└──────────────────────────────────────────────────────────────────────────┘
```

## Data classification (#3.5)

| Class | Examples | Access |
|---|---|---|
| **ALLOWED** | Time deltas, compliance %, defect rates, traffic volumes, capability indices, anonymised process parameters | GBs (read-only) and AI agents (read-only) |
| **RESTRICTED** | IP addresses, hostnames, MAC addresses, raw network logs, vendor credentials, proprietary configurations | CISO team only |
| **PROHIBITED** | Anything identifying a specific asset, person, vendor, or proprietary system | Not accessible to anyone outside CISO team |

## Query lifecycle (every query, every time)

```
1. GB or AI agent initiates query
         ↓
2. Query interface validates against data classification
   - ALLOWED patterns only (#3.5)
   - No write operations (INSERT/UPDATE/DELETE/DROP/ALTER/TRUNCATE/CREATE)
   - No restricted patterns (IP/hostname/raw data)
         ↓
3. If validation fails: DataAccessError raised; logged; rejected
         ↓
4. If validation passes: query executed against anonymised data lake
   - max_rows limit enforced (default 10000)
   - timeout_sec enforced (default 30s)
         ↓
5. Result returned to caller
   - Truncated if exceeds max_rows
         ↓
6. Audit log entry written
   - query_id, user_id, user_role, sql_hash, params_hash, row_count, truncated, elapsed_ms
```

## Parameter integrity (Poka-Yoke #3)

Process recipes (formation profile, coating weight, dosing volume, aging cycle) flow through a separate path:

```
[ Recipe Management System ]
        ↓ (recipe created/updated)
[ Track A Recipe Signer ]
   - Reads recipe, computes SHA-256 hash
   - Signs with Ed25519 key in HSM
   - Emits SignedRecipe (recipe + signature + key_id + signed_at)
        ↓
[ Signed Recipe Store ] ← in the anonymised data lake
        ↓ (PLC firmware reads signed recipe)
[ PLC Recipe Verifier ]
   - Verifies signature against Track A's public key
   - Verifies recipe hash matches
   - REJECTS if invalid (fail-closed)
   - Applies recipe to PLC registers only if valid
        ↓
[ PLC applies recipe to physical process ]
```

The signing key NEVER leaves the HSM. Even if an attacker compromises the SCADA, MES, or PLC firmware update path, they cannot forge a valid signature without the HSM-held key.

## Silent corruption detection (Layer 3 + Poka-Yoke #5)

This is the binding control for the 7 silent corruption modes (FMEA #1-7 in #4.4.3):

```
[ PLC applies signed recipe ]
        ↓
[ PLC reports observed parameter values (e.g., 4.25V when signed baseline says 4.20V) ]
        ↓
[ CISO anonymisation pipeline ]
   - Strips PLC identifiers, keeps parameter name + value + timestamp
        ↓
[ Anonymised data lake ]
        ↓
[ OT Anomaly Detection Agent ]
   - Looks up signed baseline for the parameter
   - Compares observed value vs signed expected value
   - Computes deviation %
   - If within tolerance: log only
   - If outside tolerance: SC = True Positive
     - Drift 1-5%: Tier 1 escalation
     - Drift 5-10%: Tier 2 + AUTO-ISOLATE the line
     - Drift > 10%: Tier 3 (CISO + Safety Officer) + AUTO-ISOLATE
        ↓
[ Parameter Drift Interlock (Poka-Yoke #5) ]
   - Receives isolation signal from OT Anomaly
   - Sends emergency-stop to PLC (fail-closed)
   - Logs to audit trail
        ↓
[ Defective cells do NOT continue down the line ]
```

## Hard-stop recovery (Layer 3 + SMED)

When a hard-stop event is confirmed (ransomware, OT compromise, safety event):

```
[ Confirmed cyber event from SOC Triage or OT Anomaly ]
        ↓
[ IR Automation Agent ]
   - Selects appropriate playbook (e.g., "ransomware_industrial_pc")
   - Checks CISO authorisation (pre-approved for Severity ≥ 8)
   - Executes playbook steps
        ↓
[ SMED Recovery Orchestrator ]
   - Pre-staged immutable backup hot-swapped in
   - Pre-configured restore rig powered on
   - Pre-validated golden image restored
   - Clean state validated
   - CISO notified (within 15 min for hard stop, within 1 min for safety)
        ↓
[ Line resumes production with verified state ]
```

The recovery completes in ≤ 1 hour for hard stops, ≤ 30 min for safety-critical events.

## Audit trail (every action, every query, every decision)

Every action across all four zones is logged:

- Raw data access (CISO team only): logged but not visible to GBs/agents
- Anonymisation pipeline: every transformation logged
- Data lake queries: query_id, user_id, sql_hash, params_hash, row_count, truncated, elapsed_ms
- AI agent actions: action_type, alert_id, classification, routing, severity, confidence
- Poka-Yoke enforcements: parameter, observed, expected, deviation, action, reason
- SMED executions: execution_id, step, action, target, elapsed_sec
- CISO notifications: notification_type, recipient, sla_target, actual
- Kill switch events: agent_id, reason, approver, timestamp

Audit log format: JSONL (one JSON object per line)
Audit log storage: tamper-evident (cryptographic chaining in production)
Audit log review: quarterly by CISO team; annual by third party

## What this means for the engagement

The data flow enforces the **Data-Blind Protocol** as a structural property, not a procedural one. GBs and AI agents CANNOT access raw data even if they tried — the query interface physically prevents it. This is the trust boundary that makes the engagement possible.

For the CISO: complete control over what leaves Zone 1.
For the GBs: a stable, auditable interface for the work they need to do.
For the AI agents: powerful access to the patterns they need, without the raw data they don't.
For the audit: every action is logged, every query is bounded, every boundary is enforced.
