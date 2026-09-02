# AI Agent Specifications

Four autonomous agents operating within the Data-Blind Protocol (#3.5 of the charter). Every agent:

- Queries ONLY the anonymised data lake (never raw data)
- Logs every action to the audit trail
- Has a CISO-controlled kill switch
- Has bounded resource usage (no runaway)
- Has idempotent operations (safe to retry)
- Targets Six Sigma capability (Cpk ≥ 2.0, Z ≥ 6.0)

## Agent 1: SOC Triage Agent

**Function:** Auto-classify and route SIEM alerts; suppress false positives; escalate genuine anomalies to human analysts.

**Performance target:** MTTD ≤ 2 min for known signatures (Six Sigma).

**FMEA modes addressed:** All detection modes (#1–#12 in #4.4.3).

**Inputs:**
- Anonymised SIEM events (alert ID, timestamp, severity, anonymised source/target IDs)
- Historical triage decisions (labelled training data)
- Threat intel feed (anonymised indicators)

**Outputs:**
- Alert classification (true positive / false positive / needs review)
- Severity score (1–10)
- Routing decision (auto-close, escalate to Tier 1, escalate to Tier 2)
- Audit log entry

**Constraints:**
- False positive rate ≤ 5% (Six Sigma bound)
- True positive detection rate ≥ 99.5%
- Decision latency ≤ 30 sec (well within MTTD target)
- Max 100 decisions/min (rate-limited)

**Kill switch:** CISO can disable the agent via a single config flag. All pending decisions are paused; humans take over.

## Agent 2: OT Anomaly Detection Agent

**Function:** Behavioural baselining of OT network traffic; flag deviations from signed baseline; parameter-drift detection.

**Performance target:** MTTD ≤ 10 min for novel OT anomalies (Six Sigma).

**FMEA modes addressed:** Silent corruption modes #1–#7 (the binding risk class).

**Inputs:**
- Anonymised OT telemetry (process parameters, network flows, sensor readings)
- Signed baseline recipes (cryptographically signed process parameters from Track A)
- Historical parameter distributions (anonymised)

**Outputs:**
- Anomaly score per process step (0–10)
- Drift detection (deviation from signed baseline)
- Parameter integrity verification
- Escalation to IR Automation Agent if score ≥ 7

**Constraints:**
- False positive rate ≤ 3% (tighter than SOC Triage because SC modes are higher-stakes)
- Drift detection sensitivity ≥ 99.9% for parameter changes
- Detection latency ≤ 5 min for parameter drift
- Max 1,000 parameters/second monitored

**Kill switch:** CISO can disable. Manual baseline review takes over.

## Agent 3: IR Automation Agent

**Function:** Execute pre-authorised first-response actions; isolate line segment, snapshot forensic state, notify CISO.

**Performance target:** MTTR ≤ 1 hour for hard stop (Six Sigma).

**FMEA modes addressed:** Hard stop modes #8 (formation charging), #9 (slurry ransomware), #10 (electrolyte dosing), #11 (slurry batch tracking).

**Inputs:**
- Confirmed cyber event (from SOC Triage or OT Anomaly Detection)
- Pre-authorised response playbooks (CISO-approved)
- CISO notification contact (anonymised)

**Outputs:**
- Line segment isolation (via Poka-Yoke enforcement)
- Forensic state snapshot (to immutable offline backup)
- CISO notification (within 15 min of confirmed event)
- IR cycle timestamp log
- Recovery runbook execution

**Constraints:**
- Isolation action completes ≤ 5 min (Poka-Yoke hard-coded)
- Forensic snapshot ≤ 30 min
- CISO notification ≤ 15 min
- All actions idempotent and reversible (with CISO approval)

**Kill switch:** CISO can disable. Pre-authorised playbooks remain but require human approval to execute.

## Agent 4: Threat Intel Correlation Agent

**Function:** Correlate internal telemetry with external threat intel feeds; pre-position defences against emerging campaigns.

**Performance target:** Pre-positioning within 4 hours of threat intel publication; correlation coverage ≥ 90% of industry-relevant threats.

**FMEA modes addressed:** All modes (preventive).

**Inputs:**
- Anonymised internal telemetry patterns
- External threat intel feeds (anonymised indicators)
- MITRE ATT&CK for ICS framework
- Industry peer incident reports (anonymised)

**Outputs:**
- Threat campaign identification
- Defensive pre-positioning recommendations
- FMEA delta (new modes to consider)
- Control plan update recommendations

**Constraints:**
- Pre-positioning latency ≤ 4 hours from intel publication
- Coverage ≥ 90% of industry-relevant campaigns
- False positive rate ≤ 10% (preventive context, looser than detection)
- All recommendations reviewed by Track C Lead before action

**Kill switch:** CISO can disable. Manual threat intel review takes over.

## Common interface (all 4 agents)

```python
class CyberAgent:
    """Base class for all 4 cyber resilience AI agents.

    Every agent:
    - Operates within the Data-Blind Protocol (#3.5)
    - Has a CISO-controlled kill switch
    - Logs every action to the audit trail
    - Targets Six Sigma capability (Cpk ≥ 2.0, Z ≥ 6.0)
    """

    def __init__(self, agent_id: str, config: AgentConfig, data_lake_client: DataLakeClient, audit_log: AuditLog):
        self.agent_id = agent_id
        self.config = config
        self.data_lake = data_lake_client
        self.audit = audit_log
        self.enabled = True
        self.logger = logging.getLogger(f"agent.{agent_id}")

    def is_killed(self) -> bool:
        """Check if the agent is currently disabled by CISO."""
        return not self.enabled

    def kill(self, reason: str, ciso_approver: str) -> None:
        """CISO-initiated kill switch. Logs the kill to the audit trail."""
        self.enabled = False
        self.audit.log_kill(self.agent_id, reason, ciso_approver)
        self.logger.warning(f"Agent killed: reason={reason}, approver={ciso_approver}")

    def revive(self, reason: str, ciso_approver: str) -> None:
        """CISO-authorised revival. Logs to audit trail."""
        self.enabled = True
        self.audit.log_revive(self.agent_id, reason, ciso_approver)
        self.logger.info(f"Agent revived: reason={reason}, approver={ciso_approver}")

    def log_action(self, action_type: str, details: Dict) -> None:
        """Every agent action is logged for audit."""
        self.audit.log_agent_action(self.agent_id, action_type, details)

    def query_data_lake(self, query: str, params: Dict = None) -> QueryResult:
        """Query the anonymised data lake. Bounded results, time-limited."""
        if self.is_killed():
            raise AgentKilledError(f"Agent {self.agent_id} is killed")
        self.log_action("data_lake_query", {"query": query, "params": params})
        return self.data_lake.query(query, params, max_rows=10000, timeout_sec=30)
```

## Common data types

```python
@dataclass
class AgentConfig:
    """Configuration for an AI agent."""
    agent_id: str
    description: str
    fmea_modes_addressed: List[int]  # which FMEA modes this agent handles
    mttd_target_sec: int  # target MTTD in seconds (e.g., 120 for ≤ 2 min)
    mttr_target_sec: int  # target MTTR in seconds (e.g., 3600 for ≤ 1 hour)
    false_positive_rate_max: float  # e.g., 0.05 for ≤ 5%
    true_positive_rate_min: float  # e.g., 0.995 for ≥ 99.5%
    kill_switch_path: str  # path to config file CISO can flip
    audit_log_path: str  # path to audit log

@dataclass
class QueryResult:
    """Result of a query against the anonymised data lake."""
    rows: List[Dict]
    row_count: int
    query_id: str  # logged in audit trail
    elapsed_ms: int

class AgentKilledError(Exception):
    """Raised when an agent action is attempted while killed."""
    pass
```
