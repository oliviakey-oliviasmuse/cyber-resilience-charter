"""
Base class for the 4 cyber resilience AI agents.

Every agent:
- Operates within the Data-Blind Protocol (#3.5 of the charter)
- Has a CISO-controlled kill switch
- Logs every action to the audit trail
- Targets Six Sigma capability (Cpk ≥ 2.0, Z ≥ 6.0)
- Uses bounded resource usage (no runaway)
- Has idempotent operations (safe to retry)

This is the foundation. The 4 specific agents (SOC Triage, OT Anomaly Detection,
IR Automation, Threat Intel Correlation) extend this class.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


# =============================================================================
# Common data types
# =============================================================================


class Severity(Enum):
    """Severity scale 1-10, matches the FMEA scoring system (#4.4.2 of charter)."""
    MINIMAL = 1
    LOW = 2
    MINOR = 3
    MODERATE_LOW = 4
    MODERATE = 5
    MODERATE_HIGH = 6
    HIGH = 7
    VERY_HIGH = 8
    CRITICAL = 9
    EXISTENTIAL = 10  # Severity = 10 in FMEA: safety / IP / silent corruption

    @classmethod
    def from_int(cls, n: int) -> "Severity":
        n = max(1, min(10, n))
        return cls(n)


@dataclass
class AgentConfig:
    """Configuration for an AI agent.

    Attributes:
        agent_id: Stable identifier (e.g., "soc_triage", "ot_anomaly", "ir_automation", "threat_intel")
        description: Human-readable purpose statement
        fmea_modes_addressed: List of FMEA mode numbers this agent handles (1-12, from #4.4.3)
        mttd_target_sec: Target MTTD in seconds (Six Sigma capability)
        mttr_target_sec: Target MTTR in seconds (Six Sigma capability)
        false_positive_rate_max: Maximum acceptable FPR (e.g., 0.05 for ≤ 5%)
        true_positive_rate_min: Minimum acceptable TPR (e.g., 0.995 for ≥ 99.5%)
        kill_switch_path: Path to JSON config file; CISO can flip {"enabled": false} to kill
        audit_log_path: Path to JSONL audit log
    """
    agent_id: str
    description: str
    fmea_modes_addressed: List[int]
    mttd_target_sec: int
    mttr_target_sec: int
    false_positive_rate_max: float
    true_positive_rate_min: float
    kill_switch_path: Path
    audit_log_path: Path


@dataclass
class AlertEvent:
    """An alert or anomaly event from the data lake."""
    alert_id: str
    timestamp: datetime
    severity: int  # 1-10
    fmea_mode: Optional[int] = None
    source_anonymised: str = ""
    description: str = ""
    raw_signals: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentDecision:
    """An agent's decision on an alert."""
    agent_id: str
    alert_id: str
    classification: str  # "true_positive" | "false_positive" | "needs_review"
    severity: int  # 1-10
    confidence: float  # 0-1
    routing: str  # "auto_close" | "escalate_tier_1" | "escalate_tier_2" | "escalate_tier_3"
    reasoning: str
    action_log: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Data-Blind Protocol (#3.5)
# =============================================================================


class DataLakeClient:
    """Stub for the anonymised data lake client.

    In production, this is a CISO-team-owned interface. The agent only sees
    ALLOWED data: time deltas, compliance %, defect rates, traffic volumes,
    capability indices. NEVER raw IP addresses, hostnames, or proprietary configs.

    The data lake enforces:
    - Read-only access (no writes)
    - Bounded results (max_rows)
    - Time-limited queries (timeout_sec)
    - Full query logging (every query is auditable)
    """

    def query(
        self,
        sql: str,
        params: Optional[Dict[str, Any]] = None,
        max_rows: int = 10000,
        timeout_sec: int = 30,
    ) -> "QueryResult":
        """Query the anonymised data lake.

        Args:
            sql: SQL query (only against ALLOWED tables/columns)
            params: Query parameters
            max_rows: Maximum rows to return (default 10000)
            timeout_sec: Query timeout in seconds (default 30)

        Returns:
            QueryResult with rows, row count, query_id, elapsed_ms

        Raises:
            DataAccessError: If the query violates the data-access protocol
        """
        # In production, this is the CISO-team's anonymised data lake client
        raise NotImplementedError(
            "DataLakeClient must be instantiated with the CISO-team's "
            "production anonymised data lake client"
        )


@dataclass
class QueryResult:
    rows: List[Dict[str, Any]]
    row_count: int
    query_id: str
    elapsed_ms: int


class DataAccessError(Exception):
    """Raised when an agent attempts a data access that violates #3.5."""
    pass


# =============================================================================
# Audit log
# =============================================================================


class AuditLog:
    """Append-only JSONL audit log. Every agent action is logged.

    In production, this writes to a tamper-evident log store with
    cryptographic chaining. The CISO team reviews the log quarterly.
    """

    def __init__(self, log_path: Path):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(f"audit.{log_path.stem}")

    def log_agent_action(self, agent_id: str, action_type: str, details: Dict[str, Any]) -> str:
        """Log an agent action. Returns the log entry ID for cross-reference."""
        entry_id = f"{int(time.time() * 1000)}-{agent_id}-{action_type}"
        entry = {
            "entry_id": entry_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "action_type": action_type,
            "details": details,
        }
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(f"{entry}\n")  # JSONL format
        self.logger.info(f"agent={agent_id} action={action_type} entry={entry_id}")
        return entry_id

    def log_kill(self, agent_id: str, reason: str, ciso_approver: str) -> str:
        return self.log_agent_action(agent_id, "AGENT_KILLED", {
            "reason": reason, "ciso_approver": ciso_approver
        })

    def log_revive(self, agent_id: str, reason: str, ciso_approver: str) -> str:
        return self.log_agent_action(agent_id, "AGENT_REVIVED", {
            "reason": reason, "ciso_approver": ciso_approver
        }


# =============================================================================
# Base agent
# =============================================================================


class AgentKilledError(Exception):
    """Raised when an agent action is attempted while killed."""
    pass


class CyberAgent(ABC):
    """Abstract base for all 4 cyber resilience AI agents.

    Subclass and implement: classify(), make_decision(), act_on_decision().
    """

    def __init__(self, config: AgentConfig, data_lake: DataLakeClient, audit: AuditLog):
        self.config = config
        self.data_lake = data_lake
        self.audit = audit
        self.logger = logging.getLogger(f"agent.{config.agent_id}")
        self._enabled = True
        self._actions_count = 0
        self._last_action_at: Optional[datetime] = None

    # ---- Kill switch (CISO-controlled) ----

    def is_killed(self) -> bool:
        return not self._enabled

    def kill(self, reason: str, ciso_approver: str) -> None:
        """CISO-initiated kill switch. Logs to audit trail."""
        self._enabled = False
        self.audit.log_kill(self.config.agent_id, reason, ciso_approver)
        self.logger.warning(f"KILLED reason={reason} approver={ciso_approver}")

    def revive(self, reason: str, ciso_approver: str) -> None:
        """CISO-authorised revival. Logs to audit trail."""
        self._enabled = True
        self.audit.log_revive(self.config.agent_id, reason, ciso_approver)
        self.logger.info(f"REVIVED reason={reason} approver={ciso_approver}")

    # ---- Audit and data access ----

    def log_action(self, action_type: str, details: Dict[str, Any]) -> str:
        return self.audit.log_agent_action(self.config.agent_id, action_type, details)

    def query_data_lake(
        self, sql: str, params: Optional[Dict[str, Any]] = None
    ) -> QueryResult:
        """Query the anonymised data lake. Bounded, time-limited, audited."""
        if self.is_killed():
            raise AgentKilledError(f"Agent {self.config.agent_id} is killed")
        self.log_action("data_lake_query", {"sql_hash": hash(sql), "params": params})
        return self.data_lake.query(sql, params, max_rows=10000, timeout_sec=30)

    # ---- Public entry point ----

    def process_alert(self, alert: AlertEvent) -> AgentDecision:
        """Process an alert end-to-end. Returns the agent's decision.

        Catches AgentKilledError and returns a safe decision.
        """
        if self.is_killed():
            self.logger.info(f"Skipping {alert.alert_id} - agent killed")
            return AgentDecision(
                agent_id=self.config.agent_id,
                alert_id=alert.alert_id,
                classification="needs_review",
                severity=alert.severity,
                confidence=0.0,
                routing="escalate_tier_2",
                reasoning="agent killed; routed to human review",
            )

        start = time.time()
        try:
            classification, confidence = self.classify(alert)
            decision = self.make_decision(alert, classification, confidence)
            self.act_on_decision(alert, decision)
            elapsed_ms = int((time.time() - start) * 1000)

            self.log_action("alert_processed", {
                "alert_id": alert.alert_id,
                "classification": decision.classification,
                "routing": decision.routing,
                "elapsed_ms": elapsed_ms,
            })
            self._actions_count += 1
            self._last_action_at = datetime.now(timezone.utc)
            return decision

        except AgentKilledError:
            # CISO killed the agent mid-process
            return AgentDecision(
                agent_id=self.config.agent_id,
                alert_id=alert.alert_id,
                classification="needs_review",
                severity=alert.severity,
                confidence=0.0,
                routing="escalate_tier_2",
                reasoning="agent killed mid-process",
            )

    # ---- Subclass interface ----

    @abstractmethod
    def classify(self, alert: AlertEvent) -> tuple[str, float]:
        """Classify the alert. Return (classification, confidence)."""
        ...

    @abstractmethod
    def make_decision(self, alert: AlertEvent, classification: str, confidence: float) -> AgentDecision:
        """Build the decision from the classification."""
        ...

    @abstractmethod
    def act_on_decision(self, alert: AlertEvent, decision: AgentDecision) -> None:
        """Execute the decision (e.g., escalate, snapshot, isolate)."""
        ...

    # ---- Health and metrics ----

    def health(self) -> Dict[str, Any]:
        """Return agent health metrics for the executive dashboard (Tile 5)."""
        return {
            "agent_id": self.config.agent_id,
            "enabled": not self.is_killed(),
            "actions_count": self._actions_count,
            "last_action_at": self._last_action_at.isoformat() if self._last_action_at else None,
            "fmea_modes_addressed": self.config.fmea_modes_addressed,
        }
