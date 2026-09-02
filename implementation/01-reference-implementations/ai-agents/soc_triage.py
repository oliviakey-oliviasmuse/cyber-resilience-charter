"""
SOC Triage Agent — Agent 1 of 4 in the AI-Augmented Layer 3.

Function: Auto-classify and route SIEM alerts; suppress false positives;
escalate genuine anomalies to human analysts.

Performance target: MTTD ≤ 2 min for known signatures (Six Sigma, Cpk ≥ 2.0, Z ≥ 6.0).

FMEA modes addressed: All detection modes (1-12 in #4.4.3 of the charter).
CISO kill switch: enabled via config flip. Logs every action.
Data access: anonymised data lake only (#3.5).
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from base import (
    AgentConfig,
    AgentDecision,
    AlertEvent,
    AuditLog,
    CyberAgent,
    DataLakeClient,
)


# Known-signature patterns. In production, these are maintained by Track C
# (Track B is data + metrics; Track A is architecture; Track C is automation).
# Updates flow through the FMEA control plan and Kaizen trigger #4.
KNOWN_SIGNATURES = {
    "ransomware_file_extension": {
        "pattern": r"\.(locked|crypt|enc)$",
        "severity": 10,
        "routing": "escalate_tier_2",
    },
    "lateral_movement_pattern": {
        "pattern": r"smb_enum|rdp_brute|kerberoast",
        "severity": 9,
        "routing": "escalate_tier_2",
    },
    "privilege_escalation": {
        "pattern": r"sudo_abuse|uac_bypass|tokenduplication",
        "severity": 9,
        "routing": "escalate_tier_2",
    },
    "data_exfiltration_signature": {
        "pattern": r"large_outbound|dns_tunneling|encrypted_egress",
        "severity": 8,
        "routing": "escalate_tier_2",
    },
    "ot_protocol_anomaly": {
        "pattern": r"modbus_write_unauth|s7_comm_deny|ethip_anomaly",
        "severity": 10,
        "routing": "escalate_tier_3",  # OT = safety-critical
    },
}


class SOCTriageAgent(CyberAgent):
    """SOC Triage Agent — auto-classify and route SIEM alerts.

    Decision policy:
    - High-severity known signatures (severity 9-10) → immediate Tier 2/3 escalation
    - OT protocol anomalies (always safety-critical) → Tier 3 with safety officer
    - Medium-severity known signatures → Tier 1 review
    - Low-severity or unknown → confidence-weighted auto-close or Tier 1
    - True positive rate ≥ 99.5%, False positive rate ≤ 5%
    """

    def __init__(
        self,
        config: AgentConfig,
        data_lake: DataLakeClient,
        audit: AuditLog,
        known_signatures: Optional[dict] = None,
    ):
        super().__init__(config, data_lake, audit)
        self.signatures = known_signatures or KNOWN_SIGNATURES
        self.logger.info(
            f"SOC Triage Agent initialised: {len(self.signatures)} known signatures, "
            f"FMEA modes {config.fmea_modes_addressed}"
        )

    def classify(self, alert: AlertEvent) -> tuple[str, float]:
        """Classify the alert.

        Returns:
            (classification, confidence) where:
              - classification ∈ {"true_positive", "false_positive", "needs_review"}
              - confidence ∈ [0.0, 1.0]
        """
        description = (alert.description or "").lower()
        raw = alert.raw_signals or {}

        # 1. Check against known signatures
        matched_signature = None
        for sig_name, sig in self.signatures.items():
            if re.search(sig["pattern"], description, re.IGNORECASE):
                matched_signature = (sig_name, sig)
                break

        if matched_signature:
            sig_name, sig = matched_signature
            # Known signature match → high confidence
            confidence = min(0.99, 0.85 + (alert.severity / 20))
            return "true_positive", confidence

        # 2. Heuristic: high severity + multiple raw signals → likely true positive
        signal_count = len(raw)
        if alert.severity >= 8 and signal_count >= 2:
            return "true_positive", 0.75

        if alert.severity >= 9:
            return "true_positive", 0.80

        # 3. Low severity + few signals → likely false positive
        if alert.severity <= 4 and signal_count <= 1:
            return "false_positive", 0.65

        # 4. Medium severity, ambiguous → needs review
        return "needs_review", 0.50

    def make_decision(
        self, alert: AlertEvent, classification: str, confidence: float
    ) -> AgentDecision:
        """Build the routing decision."""
        if classification == "true_positive":
            # Severity-based routing
            if alert.severity >= 9:
                routing = "escalate_tier_3"  # critical → CISO + safety
            elif alert.severity >= 7:
                routing = "escalate_tier_2"  # high → MBB + Track Lead
            else:
                routing = "escalate_tier_1"  # medium → Track Lead
        elif classification == "false_positive":
            routing = "auto_close"
        else:
            routing = "escalate_tier_1"  # needs review

        reasoning = (
            f"Classification={classification} (confidence={confidence:.2f}); "
            f"severity={alert.severity}; signals={len(alert.raw_signals or {})}; "
            f"routing={routing}"
        )

        return AgentDecision(
            agent_id=self.config.agent_id,
            alert_id=alert.alert_id,
            classification=classification,
            severity=alert.severity,
            confidence=confidence,
            routing=routing,
            reasoning=reasoning,
        )

    def act_on_decision(self, alert: AlertEvent, decision: AgentDecision) -> None:
        """Execute the decision: log, route, and notify.

        For this reference implementation, we log the action. In production:
        - "auto_close" → update SIEM, log to audit, no human action
        - "escalate_tier_1" → notify Track Lead via the engagement's communication channel
        - "escalate_tier_2" → notify MBB + Track Lead
        - "escalate_tier_3" → notify CISO + Safety Officer (immediate, ≤ 15 min SLA)
        """
        self.log_action("decision_executed", {
            "alert_id": alert.alert_id,
            "classification": decision.classification,
            "routing": decision.routing,
            "severity": decision.severity,
            "confidence": decision.confidence,
        })

        # Notify based on routing
        if decision.routing == "escalate_tier_3":
            self.logger.critical(
                f"TIER 3 ESCALATION: alert={alert.alert_id} "
                f"fmea_mode={alert.fmea_mode} severity={alert.severity}"
            )
        elif decision.routing == "escalate_tier_2":
            self.logger.warning(
                f"TIER 2 ESCALATION: alert={alert.alert_id} severity={alert.severity}"
            )
        else:
            self.logger.info(
                f"ROUTING={decision.routing}: alert={alert.alert_id}"
            )


# =============================================================================
# Production wiring (in real deployment, this is in a separate config)
# =============================================================================


def make_default_agent(
    data_lake: DataLakeClient, audit: AuditLog
) -> SOCTriageAgent:
    """Construct the default SOC Triage Agent for this engagement."""
    from pathlib import Path

    config = AgentConfig(
        agent_id="soc_triage",
        description="Auto-classify and route SIEM alerts (MTTD ≤ 2 min, Six Sigma)",
        fmea_modes_addressed=list(range(1, 13)),  # all 12 modes
        mttd_target_sec=120,  # ≤ 2 min
        mttr_target_sec=0,  # N/A — SOC Triage detects, doesn't recover
        false_positive_rate_max=0.05,
        true_positive_rate_min=0.995,
        kill_switch_path=Path("/etc/cyber-resilience/kill-switch/soc_triage.json"),
        audit_log_path=Path("/var/log/cyber-resilience/audit.jsonl"),
    )
    return SOCTriageAgent(config, data_lake, audit)


if __name__ == "__main__":
    # Quick smoke test (will fail without a real DataLakeClient)
    logging.basicConfig(level=logging.INFO)
    print("SOC Triage Agent module loaded.")
    print(f"  Known signatures: {len(KNOWN_SIGNATURES)}")
    print(f"  Targets: MTTD ≤ 2 min, TPR ≥ 99.5%, FPR ≤ 5%")
    print(f"  FMEA modes addressed: all 12")
