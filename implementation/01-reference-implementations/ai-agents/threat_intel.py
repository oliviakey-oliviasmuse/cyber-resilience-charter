"""
Threat Intel Correlation Agent — Agent 4 of 4 in the AI-Augmented Layer 3.

Function: Correlate internal telemetry with external threat intel feeds;
pre-position defences against emerging campaigns; identify FMEA deltas
when new attack patterns emerge.

Performance target: Pre-positioning within 4 hours of threat intel publication;
correlation coverage ≥ 90% of industry-relevant threats.

FMEA modes addressed: All modes (preventive — covers new attack patterns
that may not yet be in the FMEA).

Data access: anonymised data lake only (#3.5).
CISO kill switch: enabled via config flip.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from base import (
    AgentConfig,
    AgentDecision,
    AlertEvent,
    AuditLog,
    CyberAgent,
    DataLakeClient,
)


# =============================================================================
# Threat intel (anonymised)
# =============================================================================


@dataclass
class ThreatIntel:
    """A piece of threat intelligence (anonymised).

    In production, this is fetched from threat intel feeds (anonymised
    indicators only — no IP addresses, no hostnames, no proprietary
    configurations). The CISO team curates the feeds.
    """
    intel_id: str
    published_at: datetime
    threat_actor: str  # anonymised actor name (e.g., "APT-CELL-001")
    campaign: str
    target_sector: str  # e.g., "EV cell manufacturing", "OT/ICS"
    attack_patterns: List[str]  # MITRE ATT&CK for ICS technique IDs
    iocs_anonymised: List[str]  # anonymised indicators
    severity: int  # 1-10
    description: str
    recommended_actions: List[str] = field(default_factory=list)


@dataclass
class CorrelationResult:
    """Result of correlating threat intel with internal telemetry."""
    intel_id: str
    correlation_score: float  # 0-1, how well it matches our environment
    affected_systems: List[str]  # anonymised system categories
    fmea_delta: List[str]  # new FMEA modes to consider
    recommended_actions: List[str]
    pre_positioning_eta_sec: int  # how long to pre-position defences


# =============================================================================
# Threat Intel Correlation Agent
# =============================================================================


class ThreatIntelCorrelationAgent(CyberAgent):
    """Threat Intel Correlation Agent — preventive defence.

    Reads anonymised threat intel feeds, correlates with internal telemetry
    patterns (also anonymised), and produces pre-positioning recommendations.

    This is the agent with the longest lead time (preventive) but the loosest
    SLA: pre-positioning within 4 hours, FPR ≤ 10% (preventive context, looser
    than detection agents).

    Constraint: all recommendations are reviewed by Track C Lead before
    action. The agent advises; humans (or pre-authorised playbooks) decide.
    """

    def __init__(
        self,
        config: AgentConfig,
        data_lake: DataLakeClient,
        audit: AuditLog,
    ):
        super().__init__(config, data_lake, audit)
        self._intel_cache: List[ThreatIntel] = []
        self._last_refresh: Optional[datetime] = None
        self.logger.info("Threat Intel Correlation Agent initialised")

    def classify(self, alert: AlertEvent) -> tuple[str, float]:
        """Classify the threat intel event.

        For preventive correlation, "true_positive" means the threat is
        relevant to our environment. "false_positive" means the threat
        doesn't apply to EV cell manufacturing. "needs_review" means
        ambiguous.
        """
        raw = alert.raw_signals or {}
        threat_id = raw.get("intel_id", "")
        target_sector = raw.get("target_sector", "")

        # If targeting our sector, high relevance
        if "cell" in target_sector.lower() or "battery" in target_sector.lower():
            return "true_positive", 0.95
        if "ot" in target_sector.lower() or "ics" in target_sector.lower() or "manufacturing" in target_sector.lower():
            return "true_positive", 0.75
        if "energy" in target_sector.lower() or "utility" in target_sector.lower():
            # Adjacent sector
            return "needs_review", 0.50
        # Unrelated sector
        return "false_positive", 0.80

    def make_decision(
        self, alert: AlertEvent, classification: str, confidence: float
    ) -> AgentDecision:
        """Build the pre-positioning recommendation."""
        if classification == "true_positive":
            routing = "escalate_tier_2"  # Track C Lead reviews + acts
            severity = max(alert.severity, 7)
        elif classification == "needs_review":
            routing = "escalate_tier_1"  # Track Lead reviews
            severity = max(alert.severity, 5)
        else:
            routing = "auto_close"
            severity = alert.severity

        return AgentDecision(
            agent_id=self.config.agent_id,
            alert_id=alert.alert_id,
            classification=classification,
            severity=severity,
            confidence=confidence,
            routing=routing,
            reasoning=(
                f"Threat intel correlation: classification={classification} "
                f"confidence={confidence:.2f}; routing={routing}"
            ),
        )

    def act_on_decision(self, alert: AlertEvent, decision: AgentDecision) -> None:
        """Pre-position defences per the recommendation.

        For preventive correlation, the action is to update the FMEA control
        plan, update Poka-Yoke rules, and notify Track Leads. The Track C
        Lead reviews before any control plan change is finalised.
        """
        self.log_action("decision_executed", {
            "alert_id": alert.alert_id,
            "classification": decision.classification,
            "routing": decision.routing,
        })

        if decision.classification == "true_positive":
            # Update FMEA control plan
            self._update_fmea_control_plan(alert)
            # Update Poka-Yoke rules if needed
            self._update_poka_yoke_rules(alert)
            # Notify Track Leads
            self.logger.warning(
                f"THREAT INTEL RELEVANT: alert={alert.alert_id} "
                f"FMEA + Poka-Yoke updates queued for Track Lead review"
            )
        else:
            self.logger.info(f"ROUTING={decision.routing}: alert={alert.alert_id}")

    def correlate(self, intel: ThreatIntel) -> CorrelationResult:
        """Correlate a single piece of threat intel with our environment.

        Returns a CorrelationResult with score, affected systems, FMEA delta,
        and pre-positioning ETA.
        """
        self.log_action("correlation_started", {"intel_id": intel.intel_id})

        # Simple heuristic: count how many of our environment's attack
        # surfaces match the intel's attack patterns.
        our_surfaces = self._get_our_surfaces()  # from data lake
        matched = sum(1 for s in our_surfaces if s in intel.description.lower())
        score = min(1.0, matched / 5)  # 5+ matches = high confidence

        # Identify affected systems
        affected = [s for s in our_surfaces if s in intel.description.lower()]

        # Identify FMEA delta
        fmea_delta = []
        for pattern in intel.attack_patterns:
            if pattern not in ["T0830", "T0836", "T0855", "T0866"]:  # existing modes
                fmea_delta.append(pattern)

        # Pre-positioning ETA (4 hours target)
        eta = 4 * 3600 if score > 0.5 else 24 * 3600  # high-relevance: 4h, else 24h

        result = CorrelationResult(
            intel_id=intel.intel_id,
            correlation_score=score,
            affected_systems=affected,
            fmea_delta=fmea_delta,
            recommended_actions=intel.recommended_actions,
            pre_positioning_eta_sec=eta,
        )

        self.log_action("correlation_completed", {
            "intel_id": intel.intel_id,
            "score": score,
            "affected_systems": len(affected),
            "fmea_delta": len(fmea_delta),
        })

        return result

    # ---- Helpers ----

    def _get_our_surfaces(self) -> List[str]:
        """Return our environment's surface categories (anonymised).

        In production, this queries the data lake for asset categories.
        """
        return [
            "slurry_mixing",
            "electrode_coating",
            "cell_assembly",
            "electrolyte_injection",
            "formation",
            "grading",
            "bms",
            "plc",
            "scada",
            "mes",
        ]

    def _update_fmea_control_plan(self, alert: AlertEvent) -> None:
        """Queue an FMEA control plan update based on the threat intel.

        Track C Lead reviews before any change is committed.
        """
        self.log_action("fmea_update_queued", {
            "alert_id": alert.alert_id,
            "review_required_by": "track_c_lead",
        })

    def _update_poka_yoke_rules(self, alert: AlertEvent) -> None:
        """Queue a Poka-Yoke rule update based on the threat intel.

        Track A Lead reviews before any change is committed.
        """
        self.log_action("poka_yoke_update_queued", {
            "alert_id": alert.alert_id,
            "review_required_by": "track_a_lead",
        })


def make_default_agent(data_lake: DataLakeClient, audit: AuditLog) -> ThreatIntelCorrelationAgent:
    """Construct the default Threat Intel Correlation Agent."""
    from pathlib import Path

    config = AgentConfig(
        agent_id="threat_intel",
        description=(
            "Correlate threat intel with internal telemetry; pre-position "
            "defences (preventive, pre-positioning ≤ 4 hours)"
        ),
        fmea_modes_addressed=list(range(1, 13)),  # all 12 modes (preventive)
        mttd_target_sec=0,  # N/A — preventive, not detection
        mttr_target_sec=0,  # N/A — preventive
        false_positive_rate_max=0.10,  # looser (preventive context)
        true_positive_rate_min=0.90,
        kill_switch_path=Path("/etc/cyber-resilience/kill-switch/threat_intel.json"),
        audit_log_path=Path("/var/log/cyber-resilience/audit.jsonl"),
    )
    return ThreatIntelCorrelationAgent(config, data_lake, audit)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Threat Intel Correlation Agent module loaded.")
    print(f"  Targets: pre-positioning ≤ 4 hours, coverage ≥ 90%, FPR ≤ 10%")
    print(f"  All recommendations reviewed by Track C Lead before action")
    print(f"  Updates FMEA control plan + Poka-Yoke rules (queued, not auto-applied)")
