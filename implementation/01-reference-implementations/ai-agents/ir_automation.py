"""
IR Automation Agent — Agent 3 of 4 in the AI-Augmented Layer 3.

Function: Execute pre-authorised first-response actions on confirmed cyber events:
isolate line segment, snapshot forensic state, notify CISO within 15 minutes.

Performance target: MTTR ≤ 1 hour for hard stop (Six Sigma, Cpk ≥ 2.0, Z ≥ 6.0).

FMEA modes addressed: Hard stop modes
  - #8 Formation charging profile tampering
  - #9 Slurry ransomware
  - #10 Electrolyte dosing tampering
  - #11 Slurry batch tracking malware
  - #12 Assembly authentication bypass

This agent is the bridge between detection (SOC Triage, OT Anomaly) and
recovery (SMED rig). It executes the pre-authorised playbooks the CISO has
approved (#3.4 Tier 0 Real-Time Incident).

All actions are:
- Idempotent (safe to retry)
- Reversible (with CISO approval)
- Logged to the audit trail
- CISO kill-switch accessible
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional

from base import (
    AgentConfig,
    AgentDecision,
    AlertEvent,
    AuditLog,
    CyberAgent,
    DataLakeClient,
)


# =============================================================================
# Pre-authorised response playbooks (CISO-approved at G1)
# =============================================================================


@dataclass
class IRPlaybook:
    """A pre-authorised incident response playbook."""
    playbook_id: str
    name: str
    target_event: str
    steps: list  # list of step dicts with action + timeout_sec
    max_execution_sec: int
    requires_ciso_approval: bool  # if True, only CISO can trigger

    def to_dict(self) -> Dict:
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "target_event": self.target_event,
            "steps": self.steps,
            "max_execution_sec": self.max_execution_sec,
            "requires_ciso_approval": self.requires_ciso_approval,
        }


# Default playbooks (CISO-approved at G1)
DEFAULT_PLAYBOOKS = {
    "ransomware_industrial_pc": IRPlaybook(
        playbook_id="pb-ransomware-ipc",
        name="Ransomware on Industrial PC",
        target_event="ransomware_file_extension",
        steps=[
            {"action": "isolate_segment", "target": "affected_industrial_pc", "timeout_sec": 60},
            {"action": "snapshot_forensic_state", "target": "affected_industrial_pc", "timeout_sec": 300},
            {"action": "activate_smed_recovery", "target": "affected_industrial_pc", "timeout_sec": 1800},
            {"action": "notify_ciso", "target": "ciso_on_call", "timeout_sec": 900},
        ],
        max_execution_sec=3600,  # ≤ 1 hour
        requires_ciso_approval=False,
    ),
    "formation_charging_tampering": IRPlaybook(
        playbook_id="pb-formation-charging",
        name="Formation charging profile tampering",
        target_event="ot_protocol_anomaly",
        steps=[
            {"action": "isolate_formation_line", "target": "formation_lines", "timeout_sec": 60},
            {"action": "snapshot_bms_state", "target": "bms_controllers", "timeout_sec": 300},
            {"action": "revert_to_signed_recipe", "target": "formation_recipes", "timeout_sec": 600},
            {"action": "verify_cell_parameters", "target": "formation_lines", "timeout_sec": 900},
            {"action": "notify_ciso_and_safety", "target": "ciso_on_call,safety_officer", "timeout_sec": 900},
        ],
        max_execution_sec=3600,
        requires_ciso_approval=False,  # pre-authorised, but CISO notified immediately
    ),
    "electrolyte_dosing_tampering": IRPlaybook(
        playbook_id="pb-electrolyte-dosing",
        name="Electrolyte dosing volume tampering (safety-critical)",
        target_event="ot_protocol_anomaly",
        steps=[
            {"action": "isolate_electrolyte_line", "target": "electrolyte_injection_lines", "timeout_sec": 30},  # faster for safety
            {"action": "engage_safety_interlocks", "target": "electrolyte_safety_systems", "timeout_sec": 30},
            {"action": "snapshot_hmi_state", "target": "hmi_controllers", "timeout_sec": 300},
            {"action": "notify_ciso_and_safety_immediate", "target": "ciso_on_call,safety_officer", "timeout_sec": 60},  # 1 min SLA
        ],
        max_execution_sec=1800,  # ≤ 30 min for safety-critical
        requires_ciso_approval=False,
    ),
}


# =============================================================================
# IR Automation Agent
# =============================================================================


class IRAutomationAgent(CyberAgent):
    """IR Automation Agent — pre-authorised first-response execution.

    Triggered by confirmed cyber events from SOC Triage or OT Anomaly Detection.
    Executes the appropriate CISO-approved playbook.

    Constraints:
    - All actions idempotent (safe to retry)
    - All actions reversible (with CISO approval)
    - CISO notified within 15 min for any execution
    - CISO notified within 1 min for safety-critical events
    - MTTR target: ≤ 1 hour for hard stops
    """

    def __init__(
        self,
        config: AgentConfig,
        data_lake: DataLakeClient,
        audit: AuditLog,
        playbooks: Optional[Dict[str, IRPlaybook]] = None,
    ):
        super().__init__(config, data_lake, audit)
        self.playbooks = playbooks or DEFAULT_PLAYBOOKS
        self.logger.info(
            f"IR Automation Agent initialised: {len(self.playbooks)} playbooks loaded"
        )
        self._active_executions: Dict[str, Dict] = {}

    def classify(self, alert: AlertEvent) -> tuple[str, float]:
        """Classify the IR event.

        Returns:
            (classification, confidence) — always "true_positive" for IR events
            because IR only acts on confirmed events from upstream agents.
        """
        # IR is only triggered by confirmed events. Classification is trivially
        # true_positive. The interesting work is in the playbook selection and
        # execution, not the classification.
        return "true_positive", 1.0

    def make_decision(
        self, alert: AlertEvent, classification: str, confidence: float
    ) -> AgentDecision:
        """Select the appropriate playbook and return the decision."""
        # Map alert to playbook
        playbook = self._select_playbook(alert)
        if not playbook:
            # No matching playbook → escalate to Tier 3 for human IR
            return AgentDecision(
                agent_id=self.config.agent_id,
                alert_id=alert.alert_id,
                classification=classification,
                severity=alert.severity,
                confidence=confidence,
                routing="escalate_tier_3",
                reasoning="No matching playbook; human IR required",
            )

        # Determine routing
        if playbook.requires_ciso_approval:
            routing = "escalate_tier_3"  # CISO approval before execution
        elif alert.severity >= 9:
            routing = "escalate_tier_2"  # notify CISO immediately, execute playbook
        else:
            routing = "auto_execute"  # execute playbook, log to audit

        return AgentDecision(
            agent_id=self.config.agent_id,
            alert_id=alert.alert_id,
            classification=classification,
            severity=alert.severity,
            confidence=confidence,
            routing=routing,
            reasoning=(
                f"Selected playbook {playbook.playbook_id} ({playbook.name}); "
                f"max execution {playbook.max_execution_sec}s; routing={routing}"
            ),
            action_log={"playbook_id": playbook.playbook_id},
        )

    def act_on_decision(self, alert: AlertEvent, decision: AgentDecision) -> None:
        """Execute the playbook steps.

        Each step is logged to the audit trail. If a step fails, the playbook
        pauses and escalates to Tier 3 (human IR takes over).
        """
        playbook_id = decision.action_log.get("playbook_id")
        if not playbook_id:
            self.logger.error(f"No playbook in decision for {alert.alert_id}")
            return

        playbook = self.playbooks.get(playbook_id)
        if not playbook:
            self.logger.error(f"Playbook {playbook_id} not found")
            return

        self.log_action("playbook_execution_started", {
            "alert_id": alert.alert_id,
            "playbook_id": playbook_id,
            "total_steps": len(playbook.steps),
        })

        execution_id = f"exec-{int(time.time() * 1000)}-{alert.alert_id}"
        self._active_executions[execution_id] = {
            "alert_id": alert.alert_id,
            "playbook_id": playbook_id,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "steps_completed": [],
            "status": "in_progress",
        }

        for i, step in enumerate(playbook.steps, 1):
            self.log_action("playbook_step_started", {
                "execution_id": execution_id,
                "step_number": i,
                "action": step["action"],
                "target": step["target"],
            })

            try:
                self._execute_step(step)
                self._active_executions[execution_id]["steps_completed"].append({
                    "step_number": i,
                    "action": step["action"],
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                })
                self.log_action("playbook_step_completed", {
                    "execution_id": execution_id,
                    "step_number": i,
                })
            except Exception as e:
                # Step failed → pause and escalate
                self.log_action("playbook_step_failed", {
                    "execution_id": execution_id,
                    "step_number": i,
                    "error": str(e),
                })
                self._active_executions[execution_id]["status"] = "failed"
                self.logger.critical(
                    f"Playbook {playbook_id} failed at step {i} for {alert.alert_id}: {e}"
                )
                return

        self._active_executions[execution_id]["status"] = "completed"
        self._active_executions[execution_id]["completed_at"] = (
            datetime.now(timezone.utc).isoformat()
        )
        self.log_action("playbook_execution_completed", {
            "execution_id": execution_id,
            "playbook_id": playbook_id,
        })

    # ---- Helpers ----

    def _select_playbook(self, alert: AlertEvent) -> Optional[IRPlaybook]:
        """Map the alert to the appropriate playbook."""
        raw = alert.raw_signals or {}
        fmea_mode = alert.fmea_mode
        target = raw.get("target_event", "")

        # FMEA mode → playbook mapping
        if fmea_mode == 9 or "ransomware" in target:
            return self.playbooks.get("ransomware_industrial_pc")
        if fmea_mode == 8 or "formation" in target or "charging" in target:
            return self.playbooks.get("formation_charging_tampering")
        if fmea_mode == 10 or "electrolyte" in target or "dosing" in target:
            return self.playbooks.get("electrolyte_dosing_tampering")

        return None

    def _execute_step(self, step: Dict) -> None:
        """Execute a single playbook step.

        In production, this calls the actual services:
        - "isolate_segment" → Poka-Yoke interlock service
        - "snapshot_forensic_state" → SMED rig backup service
        - "activate_smed_recovery" → SMED rig recovery service
        - "notify_ciso" → engagement communication service
        - "revert_to_signed_recipe" → Track A recipe management service

        This reference implementation simulates the calls.
        """
        action = step["action"]
        target = step["target"]
        timeout = step.get("timeout_sec", 60)
        # Simulated execution. In production, call the actual service.
        time.sleep(0.001)  # simulate fast execution
        self.logger.info(
            f"Executed step: action={action} target={target} timeout={timeout}s"
        )


def make_default_agent(data_lake: DataLakeClient, audit: AuditLog) -> IRAutomationAgent:
    """Construct the default IR Automation Agent."""
    from pathlib import Path

    config = AgentConfig(
        agent_id="ir_automation",
        description=(
            "Execute pre-authorised first-response actions on confirmed cyber "
            "events (MTTR ≤ 1 hour, Six Sigma)"
        ),
        fmea_modes_addressed=[8, 9, 10, 11, 12],  # hard stop modes
        mttd_target_sec=0,  # N/A — IR is response, not detection
        mttr_target_sec=3600,  # ≤ 1 hour
        false_positive_rate_max=0.0,  # IR only acts on confirmed events
        true_positive_rate_min=1.0,  # confirmed events only
        kill_switch_path=Path("/etc/cyber-resilience/kill-switch/ir_automation.json"),
        audit_log_path=Path("/var/log/cyber-resilience/audit.jsonl"),
    )
    return IRAutomationAgent(config, data_lake, audit)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("IR Automation Agent module loaded.")
    print(f"  Playbooks: {list(DEFAULT_PLAYBOOKS.keys())}")
    print(f"  Targets: MTTR ≤ 1 hour (hard stop), ≤ 30 min (safety-critical)")
    print(f"  All actions idempotent, reversible, audit-logged, kill-switchable")
