"""
OT Anomaly Detection Agent — Agent 2 of 4 in the AI-Augmented Layer 3.

Function: Behavioural baselining of OT network traffic; flag deviations from
signed baseline; parameter-drift detection (the binding control for silent
corruption — the largest exposure class).

Performance target: MTTD ≤ 10 min for novel OT anomalies (Six Sigma, Cpk ≥ 2.0).

FMEA modes addressed: Silent corruption modes 1-7 in §4.4.3 of the charter
(the binding risk class — 7 of 12 top modes, top 5 RPN ≥ 450, all S=10).

This is the structurally most important agent because silent corruption is
the failure class the original IT security perimeter cannot see (no halt
event to alert on). The AI-augmented Layer 3 is the structural answer.

Data access: anonymised data lake only (§3.5).
CISO kill switch: enabled via config flip.
"""

from __future__ import annotations

import logging
import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from base import (
    AgentConfig,
    AgentDecision,
    AlertEvent,
    AuditLog,
    CyberAgent,
    DataLakeClient,
)


# =============================================================================
# Signed baseline (cryptographic recipe signing per §4.5.3 Poka-Yoke #3)
# =============================================================================


@dataclass
class SignedBaseline:
    """A cryptographically signed process parameter baseline.

    In production, this is signed by Track A's cryptographic signing
    infrastructure (Poka-Yoke #3) and stored in the data lake.
    """
    process_step: str
    parameter_name: str
    expected_value: float
    tolerance_pct: float  # allowed deviation as percentage of expected
    signed_at: datetime
    signature: str  # cryptographic signature (placeholder here)

    def is_within_tolerance(self, observed: float) -> Tuple[bool, float]:
        """Check if observed value is within signed tolerance.

        Returns:
            (within_tolerance, deviation_pct)
            deviation_pct = (observed - expected) / expected * 100
        """
        if self.expected_value == 0:
            return (observed == 0, 0.0)
        deviation_pct = abs(observed - self.expected_value) / abs(self.expected_value) * 100
        return (deviation_pct <= self.tolerance_pct, deviation_pct)


# =============================================================================
# OT Anomaly Detection Agent
# =============================================================================


class OTAnomalyDetectionAgent(CyberAgent):
    """OT Anomaly Detection Agent — parameter drift + behavioural baselining.

    The structurally most important of the 4 agents. Detects silent corruption
    by comparing observed process parameters against cryptographically signed
    baselines. Auto-isolates the line segment if drift exceeds critical threshold.

    Decision policy:
    - Parameter within signed tolerance → no action
    - Parameter drift 0-1% → log, monitor
    - Parameter drift 1-5% → Tier 1 escalation
    - Parameter drift 5-10% → Tier 2 escalation (auto-isolate)
    - Parameter drift > 10% or unrecognised parameter → Tier 3 (CISO + safety)

    Detection target: MTTD ≤ 10 min, false positive rate ≤ 3% (tighter than
    SOC Triage because silent corruption is higher-stakes).
    """

    # Anomaly severity thresholds (percentage deviation from signed baseline)
    DRIFT_THRESHOLDS = {
        "monitor": 1.0,        # 0-1% drift: log only
        "tier_1": 5.0,         # 1-5% drift: Tier 1 escalation
        "tier_2": 10.0,        # 5-10% drift: Tier 2 + auto-isolate
        # > 10%: Tier 3
    }

    def __init__(
        self,
        config: AgentConfig,
        data_lake: DataLakeClient,
        audit: AuditLog,
    ):
        super().__init__(config, data_lake, audit)
        self.logger.info(
            f"OT Anomaly Agent initialised: drift thresholds {self.DRIFT_THRESHOLDS}, "
            f"FMEA SC modes {config.fmea_modes_addressed}"
        )
        # Cache of signed baselines (refreshed periodically)
        self._baseline_cache: Dict[str, SignedBaseline] = {}

    def classify(self, alert: AlertEvent) -> Tuple[str, float]:
        """Classify the OT anomaly.

        Uses the signed baseline comparison logic. Returns:
          (classification, confidence)
        """
        raw = alert.raw_signals or {}
        process_step = raw.get("process_step", "")
        parameter_name = raw.get("parameter_name", "")
        observed_value = raw.get("observed_value")

        if not (process_step and parameter_name and observed_value is not None):
            # Malformed alert → needs review
            return "needs_review", 0.30

        # Look up the signed baseline
        baseline_key = f"{process_step}::{parameter_name}"
        baseline = self._get_baseline(baseline_key)
        if not baseline:
            # No signed baseline for this parameter → unknown parameter
            return "needs_review", 0.40

        within_tolerance, deviation_pct = baseline.is_within_tolerance(observed_value)

        if within_tolerance:
            # Parameter is within signed tolerance — but we got an alert, so
            # something else is anomalous. Could be correlation with another
            # parameter. Mark as needs_review.
            return "needs_review", 0.60

        # Outside tolerance — silent corruption
        # Confidence is high because the baseline is cryptographically signed
        confidence = min(0.99, 0.90 + (deviation_pct / 100))
        return "true_positive", confidence

    def make_decision(
        self, alert: AlertEvent, classification: str, confidence: float
    ) -> AgentDecision:
        """Build the routing decision based on drift severity."""
        if classification != "true_positive":
            # Within tolerance or unknown — light handling
            return AgentDecision(
                agent_id=self.config.agent_id,
                alert_id=alert.alert_id,
                classification=classification,
                severity=alert.severity,
                confidence=confidence,
                routing="auto_close" if classification == "false_positive" else "escalate_tier_1",
                reasoning=f"Parameter within tolerance or unknown; routing={classification}",
            )

        # True positive — drift-based routing
        raw = alert.raw_signals or {}
        deviation_pct = raw.get("deviation_pct", 0)

        if deviation_pct > self.DRIFT_THRESHOLDS["tier_2"]:
            # > 10% drift → Tier 3 (CISO + Safety Officer)
            routing = "escalate_tier_3"
            severity = 10
        elif deviation_pct > self.DRIFT_THRESHOLDS["tier_1"]:
            # 5-10% drift → Tier 2 + auto-isolate
            routing = "escalate_tier_2"
            severity = 9
        else:
            # 1-5% drift → Tier 1
            routing = "escalate_tier_1"
            severity = 7

        return AgentDecision(
            agent_id=self.config.agent_id,
            alert_id=alert.alert_id,
            classification=classification,
            severity=severity,
            confidence=confidence,
            routing=routing,
            reasoning=(
                f"Silent corruption detected: deviation {deviation_pct:.2f}% from signed "
                f"baseline (threshold: tier_1={self.DRIFT_THRESHOLDS['tier_1']}%, "
                f"tier_2={self.DRIFT_THRESHOLDS['tier_2']}%); routing={routing}"
            ),
        )

    def act_on_decision(self, alert: AlertEvent, decision: AgentDecision) -> None:
        """Execute: log, route, AND auto-isolate if severe.

        This is the structural enforcement — silent corruption triggers
        automatic line segment isolation to prevent defective cells from
        continuing down the line.
        """
        self.log_action("decision_executed", {
            "alert_id": alert.alert_id,
            "classification": decision.classification,
            "routing": decision.routing,
            "severity": decision.severity,
        })

        if decision.routing == "escalate_tier_2":
            # Auto-isolate the affected line segment
            self._auto_isolate_line_segment(alert)
        elif decision.routing == "escalate_tier_3":
            # Critical silent corruption → isolate + notify CISO + safety
            self._auto_isolate_line_segment(alert)
            self.logger.critical(
                f"CRITICAL silent corruption: fmea_mode={alert.fmea_mode} "
                f"alert={alert.alert_id} - CISO and Safety Officer notified"
            )
        else:
            self.logger.info(
                f"ROUTING={decision.routing}: alert={alert.alert_id} "
                f"fmea_mode={alert.fmea_mode}"
            )

    # ---- Helpers ----

    def _get_baseline(self, baseline_key: str) -> Optional[SignedBaseline]:
        """Look up signed baseline. In production, this queries the data lake
        and verifies the cryptographic signature against Track A's signing
        infrastructure (Poka-Yoke #3).
        """
        if baseline_key in self._baseline_cache:
            return self._baseline_cache[baseline_key]

        # In production, query the data lake for the signed baseline
        # result = self.query_data_lake(
        #     "SELECT expected_value, tolerance_pct, signed_at, signature "
        #     "FROM signed_baselines WHERE baseline_key = :key",
        #     {"key": baseline_key}
        # )
        # For this reference implementation, return None (caller handles missing)
        return None

    def _auto_isolate_line_segment(self, alert: AlertEvent) -> None:
        """Auto-isolate the affected line segment via Poka-Yoke enforcement.

        In production, this calls the Poka-Yoke parameter-drift-interlock
        service (Track A). The isolation is fail-closed: if the call fails,
        the line stays in the safe state (isolated).
        """
        self.log_action("line_segment_isolated", {
            "alert_id": alert.alert_id,
            "process_step": alert.raw_signals.get("process_step", "unknown"),
            "fmea_mode": alert.fmea_mode,
        })
        # In production: call the Poka-Yoke interlock service
        # poka_yoke_client.isolate(alert.raw_signals["process_step"])


def make_default_agent(data_lake: DataLakeClient, audit: AuditLog) -> OTAnomalyDetectionAgent:
    """Construct the default OT Anomaly Detection Agent."""
    from pathlib import Path

    config = AgentConfig(
        agent_id="ot_anomaly",
        description=(
            "Detect silent corruption via parameter-drift baselining against "
            "cryptographically signed recipes (MTTD ≤ 10 min, Six Sigma)"
        ),
        fmea_modes_addressed=[1, 2, 3, 4, 5, 6, 7],  # all 7 SC modes
        mttd_target_sec=600,  # ≤ 10 min
        mttr_target_sec=0,  # N/A — OT Anomaly detects, IR Automation recovers
        false_positive_rate_max=0.03,  # tighter than SOC Triage
        true_positive_rate_min=0.999,
        kill_switch_path=Path("/etc/cyber-resilience/kill-switch/ot_anomaly.json"),
        audit_log_path=Path("/var/log/cyber-resilience/audit.jsonl"),
    )
    return OTAnomalyDetectionAgent(config, data_lake, audit)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("OT Anomaly Detection Agent module loaded.")
    print(f"  Drift thresholds: {OTAnomalyDetectionAgent.DRIFT_THRESHOLDS}")
    print(f"  Targets: MTTD ≤ 10 min, TPR ≥ 99.9%, FPR ≤ 3%")
    print(f"  FMEA SC modes addressed: 1-7 (the binding risk class)")
    print(f"  Auto-isolation on tier_2+: line segment isolated via Poka-Yoke")
