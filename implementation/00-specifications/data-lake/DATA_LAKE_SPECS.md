# Anonymised Data Lake Specifications

The anonymised data lake is the CISO-team-owned data store that the 19 Green Belts and the 4 AI agents query. It enforces the Data-Blind Protocol (§3.5 of the charter).

## Charter reference

§3.5 Data-Access Governance (the Data-Blind Protocol).

## Trust boundary

```
┌──────────────────────────────────────────────────────────────────┐
│ ZONE 1: RAW DATA  (CISO team only)                                │
│   - IP addresses, hostnames, MAC, raw logs, credentials            │
└──────────────────────────────┬───────────────────────────────────┘
                               │ only CISO anonymisation pipeline
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ ZONE 2: ANONYMISED DATA LAKE  (GB + AI agent access, read-only)  │
│   - Only ALLOWED outputs: time deltas, compliance %, etc.         │
│   - Bounded queries, audit-logged                                  │
└──────────────────────────────────────────────────────────────────┘
```

## Data classification (§3.5)

| Class | Examples | GB access | AI agent access |
|---|---|---|---|
| **ALLOWED** | Time deltas (MTTD, MTTR, cycle time), compliance % (patch, MFA), defect rates, traffic volumes, capability indices (Cpk, Z-score, DPMO), anonymised process parameters, FMEA aggregates (RPN, S/O/D averages) | Read-only via query interface | Read-only via query interface |
| **RESTRICTED** | IP addresses, hostnames, MAC addresses, raw network logs, vendor credentials, proprietary configurations, private keys | ❌ NEVER accessible | ❌ NEVER accessible |
| **PROHIBITED** | Anything identifying a specific asset, person, vendor, or proprietary system | ❌ NEVER accessible | ❌ NEVER accessible |

## Schema (logical)

The anonymised data lake is a relational database (PostgreSQL or similar) with the following logical tables. **Only ALLOWED columns exist.** RESTRICTED and PROHIBITED data never enters the lake.

### Table: `detection_events`

```sql
CREATE TABLE detection_events (
    event_id          VARCHAR(64) PRIMARY KEY,    -- anonymised event ID
    timestamp         TIMESTAMP NOT NULL,         -- event timestamp
    fmea_mode         INT,                        -- FMEA mode 1-12
    severity          INT NOT NULL,               -- 1-10
    classification    VARCHAR(32),                -- true_positive | false_positive | needs_review
    confidence        DECIMAL(4, 3),              -- 0.000 - 1.000
    mttd_sec          INT,                        -- MTTD in seconds (for detections)
    agent_id          VARCHAR(32),                -- detecting agent
    audit_log_id      VARCHAR(64),                -- log entry ID
    -- NO IP, hostname, MAC, raw data
    INDEX idx_timestamp (timestamp),
    INDEX idx_fmea_mode (fmea_mode)
);
```

### Table: `response_events`

```sql
CREATE TABLE response_events (
    event_id          VARCHAR(64) PRIMARY KEY,
    timestamp         TIMESTAMP NOT NULL,
    fmea_mode         INT,
    severity          INT NOT NULL,
    mttr_sec          INT,                        -- MTTR in seconds
    playbook_id       VARCHAR(64),                -- SMED playbook executed
    execution_status  VARCHAR(32),                -- completed | failed | in_progress
    agent_id          VARCHAR(32),                -- IR Automation agent
    audit_log_id      VARCHAR(64),
    INDEX idx_timestamp (timestamp),
    INDEX idx_fmea_mode (fmea_mode)
);
```

### Table: `capability_metrics`

```sql
CREATE TABLE capability_metrics (
    metric_id         VARCHAR(64) PRIMARY KEY,
    timestamp         TIMESTAMP NOT NULL,
    sub_process       VARCHAR(64) NOT NULL,        -- e.g., "detection_known"
    cpk               DECIMAL(5, 3),              -- Cpk value
    z_score           DECIMAL(5, 3),              -- Z-score
    dpmo              DECIMAL(10, 4),             -- DPMO
    sample_size       INT,
    -- All ALLOWED (aggregate capability metrics)
    INDEX idx_sub_process_timestamp (sub_process, timestamp)
);
```

### Table: `patch_compliance`

```sql
CREATE TABLE patch_compliance (
    record_id         VARCHAR(64) PRIMARY KEY,
    timestamp         TIMESTAMP NOT NULL,
    asset_category    VARCHAR(64) NOT NULL,        -- e.g., "industrial_pc"
    compliance_pct    DECIMAL(5, 2),              -- 0.00 - 100.00
    compliant_count   INT,
    total_count       INT,
    INDEX idx_timestamp (timestamp),
    INDEX idx_asset_category (asset_category)
);
```

### Table: `signed_baselines` (for parameter drift detection)

```sql
CREATE TABLE signed_baselines (
    baseline_id       VARCHAR(64) PRIMARY KEY,
    process_step      VARCHAR(64) NOT NULL,        -- e.g., "formation"
    parameter_name    VARCHAR(64) NOT NULL,        -- e.g., "charging_voltage"
    expected_value    DECIMAL(15, 6) NOT NULL,
    tolerance_pct     DECIMAL(5, 3) NOT NULL,      -- e.g., 2.0 for ±2%
    signed_at         TIMESTAMP NOT NULL,
    signature         VARCHAR(256) NOT NULL,       -- Ed25519 base64
    signing_key_id    VARCHAR(64) NOT NULL,
    INDEX idx_process_step_parameter (process_step, parameter_name)
);
```

### Table: `fmea_register`

```sql
CREATE TABLE fmea_register (
    mode_id           INT PRIMARY KEY,             -- 1-12
    process_step      VARCHAR(64) NOT NULL,
    failure_mode      VARCHAR(512) NOT NULL,
    severity          INT NOT NULL,               -- 1-10
    occurrence        INT NOT NULL,               -- 1-10
    detection         INT NOT NULL,               -- 1-10
    rpn               INT NOT NULL,               -- severity × occurrence × detection
    high_risk_root_cause VARCHAR(512),
    last_refresh      TIMESTAMP NOT NULL,
    INDEX idx_rpn (rpn DESC)
);
```

### Table: `kaizen_events`

```sql
CREATE TABLE kaizen_events (
    event_id          VARCHAR(64) PRIMARY KEY,
    timestamp         TIMESTAMP NOT NULL,
    trigger_id        INT NOT NULL,               -- 1-13
    trigger_name      VARCHAR(64) NOT NULL,
    description       VARCHAR(2048),
    status            VARCHAR(32),                -- open | in_progress | closed
    a3_id             VARCHAR(64),
    closed_at         TIMESTAMP,
    INDEX idx_trigger (trigger_id),
    INDEX idx_status (status)
);
```

### Table: `maturity_scores`

```sql
CREATE TABLE maturity_scores (
    score_id          VARCHAR(64) PRIMARY KEY,
    timestamp         TIMESTAMP NOT NULL,
    level             INT NOT NULL,               -- 1-5
    score             DECIMAL(4, 2),              -- 0.00 - 16.00 (8 sub-indicators × 2)
    sub_indicators    JSON,                       -- {"standard_work": 2, "fmea": 2, ...}
    external_validation VARCHAR(64),
    INDEX idx_timestamp (timestamp)
);
```

### Table: `audit_log` (read-only view)

```sql
CREATE VIEW v_audit_log AS
SELECT
    entry_id,
    timestamp,
    agent_id,                  -- 'green_belt' | 'ai_agent' | 'ciso' | 'system'
    action_type,               -- 'data_lake_query' | 'data_lake_write_attempt' | etc.
    details                    -- JSON
FROM audit_log_store;
-- Note: actual audit log storage is in a tamper-evident external store
```

## Query interface

The query interface is the ONLY way GBs and AI agents can access the data lake.

### Interface

```python
AnonymisedDataLake.query(
    sql: str,
    params: Optional[Dict] = None,
    max_rows: Optional[int] = None,         # default 10000
    timeout_sec: Optional[int] = None,     # default 30
    user_id: str = "unknown",
    user_role: str = "green_belt",
) -> QueryResult
```

### Validation (Layer 2 enforcement)

Before any query executes:

1. **Pattern validation:** check for RESTRICTED patterns (IP, hostname, MAC, raw data) — reject with `DataAccessError`
2. **Operation validation:** check for write operations (INSERT/UPDATE/DELETE/DROP/ALTER/TRUNCATE/CREATE) — reject with `DataAccessError`
3. **Bounded execution:** apply max_rows limit, timeout_sec limit
4. **Audit logging:** log every query (query_id, user_id, sql_hash, params_hash, row_count, elapsed_ms)

### Access control (Layer 3 enforcement)

- **Per-user credentials** with MFA
- **Per-role authorization** (Track A / B / C)
- **Session timeout** (8 hours)
- **Audit log review** (monthly by CISO team)

## Properties

- **Read-only:** No write operations allowed
- **Bounded:** max_rows, timeout_sec prevent resource exhaustion
- **Auditable:** Every query logged to immutable store
- **Anonymous:** No PII, no IP, no proprietary data
- **Fast:** Indexed on common query patterns
- **Six Sigma-aligned:** Supports Z ≥ 6.0 capability targets

## Reference implementation

- `01-reference-implementations/data-lake/query_interface.py`
- `AnonymisedDataLake` class with `query()` method
- ALLOWED_PATTERNS and RESTRICTED_PATTERNS lists
- Audit log integration

## Deployment

- CISO team owns the production data lake
- CISO team owns the anonymisation pipeline
- Track B (Data & Metrics) uses the query interface for SPC charts, FMEA refresh, capability reporting
- All 4 AI agents use the query interface (read-only)
- Anonymisation pipeline is NOT in this folder (CISO-team owned)

## Failure modes

| Failure | Response |
|---|---|
| Query timeout | Return partial results; log timeout event |
| Query exceeds max_rows | Truncate; log truncation event |
| Query accesses restricted data | Reject with DataAccessError; log security event; Tier 2 escalation |
| Query attempts write operation | Reject with DataAccessError; log security event; Tier 2 escalation |
| Anonymisation pipeline fails | CISO team fallback to manual anonymised queries; Tier 3 escalation |
| Data lake unavailable | CISO team fallback; manual mode; Tier 3 escalation |

## Performance targets

- Query latency P95 ≤ 5 seconds (for standard queries)
- Query latency P99 ≤ 30 seconds (timeout threshold)
- Uptime ≥ 99.5% (matches Six Sigma capability target)
- Audit log retention: 7 years minimum
