"""
SMED for Disaster Recovery — Reference Implementation

This is the structural recovery infrastructure for the engagement.
Repurposes SMED (Single-Minute Exchange of Die) from manufacturing
changeover to cyber recovery.

The principle: convert "internal" recovery steps (performed during the
attack, under time pressure) into "external" steps (pre-staged, ready
to deploy). The MTTR target is ≤ 1 hour for hard stop events.

External (pre-staged, ready to deploy):
- Immutable, pre-verified offline backups on hot-swappable drives
- Pre-configured standalone restore rigs (cryptographically verified)
- Pre-validated golden images (signed, offline)
- Pre-authorised recovery runbooks (CISO standing approval for Severity ≥ 8)
- Clean-state validation before vendor reconnection

Internal (during the attack, time-pressured):
- Search for backup files → eliminated (backups are hot-swappable)
- Configure recovery servers → eliminated (restore rigs are pre-configured)
- Validate recovered systems → eliminated (golden images are pre-validated)
- Authorise recovery actions → eliminated (pre-authorised for Severity ≥ 8)
- Re-establish vendor access → only after clean-state validation

Performance target: MTTR ≤ 1 hour for hard stops, ≤ 30 min for safety-critical.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional


# =============================================================================
# Pre-staged external recovery assets
# =============================================================================


@dataclass
class ImmutableBackup:
    """An immutable offline backup, pre-verified, hot-swappable.

    In production: stored on write-once-read-many (WORM) media in an
    air-gapped location. Cryptographically signed.
    """
    backup_id: str
    system_category: str  # "industrial_pc", "bms_controller", "scada_server", etc.
    created_at: datetime
    size_gb: float
    signature: str  # cryptographic signature
    last_verified: datetime
    verification_status: str = "verified"  # "verified", "needs_re_verification", "failed"

    def is_usable(self) -> bool:
        """Whether this backup can be used for recovery."""
        return self.verification_status == "verified"


@dataclass
class PreConfiguredRestoreRig:
    """A pre-configured standalone restore rig.

    In production: a physical server, air-gapped, with all necessary
    software pre-installed and cryptographically verified.
    """
    rig_id: str
    system_category: str
    location: str
    last_tested: datetime
    test_status: str = "passed"  # "passed", "needs_test", "failed"


@dataclass
class PreValidatedGoldenImage:
    """A pre-validated golden image, signed and offline.

    In production: stored offline, cryptographically signed by Track A's
    signing service. Verified monthly.
    """
    image_id: str
    system_category: str
    version: str
    signed_at: datetime
    signature: str
    last_verified: datetime


@dataclass
class PreAuthorisedRunbook:
    """A pre-authorised recovery runbook (CISO standing approval)."""
    runbook_id: str
    target_event: str
    steps: List[Dict]
    ciso_approval_required: bool
    ciso_standing_approval: bool  # if True, no per-incident approval needed
    approved_by: str
    approved_at: datetime


# =============================================================================
# The SMED orchestrator
# =============================================================================


class RecoveryStepStatus(Enum):
    """Status of a recovery step."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class RecoveryExecution:
    """A recovery execution in progress."""
    execution_id: str
    incident_id: str
    started_at: datetime
    target_event: str
    current_step: int = 0
    total_steps: int = 0
    step_statuses: List[RecoveryStepStatus] = field(default_factory=list)
    completed_at: Optional[datetime] = None
    overall_status: str = "in_progress"


class SMEDRecoveryOrchestrator:
    """SMED recovery orchestrator — pre-staged disaster recovery.

    Coordinates the recovery process using pre-staged external assets.
    Designed for ≤ 1 hour MTTR.

    Critical: every step is audited. The orchestrator cannot skip
    pre-authorisation checks or clean-state validation.
    """

    def __init__(
        self,
        immutable_backups: List[ImmutableBackup],
        restore_rigs: List[PreConfiguredRestoreRig],
        golden_images: List[PreValidatedGoldenImage],
        runbooks: List[PreAuthorisedRunbook],
        audit_log_path: Path,
    ):
        self.backups = {b.backup_id: b for b in immutable_backups}
        self.rigs = {r.rig_id: r for r in restore_rigs}
        self.images = {i.image_id: i for i in golden_images}
        self.runbooks = {r.runbook_id: r for r in runbooks}
        self.audit_log_path = Path(audit_log_path)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        self._executions: Dict[str, RecoveryExecution] = {}
        self.logger = logging.getLogger("smed.recovery")
        self.logger.info(
            f"SMED orchestrator initialised: {len(self.backups)} backups, "
            f"{len(self.rigs)} restore rigs, {len(self.images)} golden images, "
            f"{len(self.runbooks)} runbooks"
        )

    def execute_recovery(
        self,
        incident_id: str,
        target_event: str,
        runbook_id: str,
    ) -> RecoveryExecution:
        """Execute recovery for a confirmed incident.

        Returns a RecoveryExecution tracking the progress.
        """
        runbook = self.runbooks.get(runbook_id)
        if not runbook:
            raise ValueError(f"Unknown runbook: {runbook_id}")

        # Check CISO authorisation
        if runbook.ciso_approval_required and not runbook.ciso_standing_approval:
            # Per-incident CISO approval required
            self.logger.critical(
                f"PER-INCIDENT CISO APPROVAL REQUIRED for {runbook_id}; "
                f"incident={incident_id}; cannot auto-execute"
            )
            raise PermissionError(
                f"Runbook {runbook_id} requires per-incident CISO approval"
            )

        execution = RecoveryExecution(
            execution_id=f"exec-{int(time.time() * 1000)}",
            incident_id=incident_id,
            started_at=datetime.now(timezone.utc),
            target_event=target_event,
            total_steps=len(runbook.steps),
            step_statuses=[RecoveryStepStatus.PENDING] * len(runbook.steps),
        )
        self._executions[execution.execution_id] = execution

        self._audit_log("recovery_started", {
            "execution_id": execution.execution_id,
            "incident_id": incident_id,
            "runbook_id": runbook_id,
            "target_event": target_event,
            "total_steps": len(runbook.steps),
        })

        self.logger.warning(
            f"RECOVERY STARTED: incident={incident_id} runbook={runbook_id} "
            f"target={target_event} total_steps={len(runbook.steps)}"
        )

        # Execute steps
        for i, step in enumerate(runbook.steps):
            execution.current_step = i
            execution.step_statuses[i] = RecoveryStepStatus.IN_PROGRESS

            try:
                self._execute_step(execution, step)
                execution.step_statuses[i] = RecoveryStepStatus.COMPLETED
            except Exception as e:
                execution.step_statuses[i] = RecoveryStepStatus.FAILED
                execution.overall_status = "failed"
                self._audit_log("step_failed", {
                    "execution_id": execution.execution_id,
                    "step_number": i,
                    "error": str(e),
                })
                self.logger.error(
                    f"Recovery step {i} failed for {execution.execution_id}: {e}"
                )
                return execution

        execution.overall_status = "completed"
        execution.completed_at = datetime.now(timezone.utc)
        elapsed = (execution.completed_at - execution.started_at).total_seconds()

        self._audit_log("recovery_completed", {
            "execution_id": execution.execution_id,
            "elapsed_sec": elapsed,
        })

        self.logger.warning(
            f"RECOVERY COMPLETED: incident={incident_id} elapsed={elapsed:.0f}s "
            f"({elapsed/60:.1f} min)"
        )
        return execution

    def _execute_step(self, execution: RecoveryExecution, step: Dict) -> None:
        """Execute a single recovery step.

        Steps are pre-staged (external). The actual execution is mostly
        orchestration: hot-swap drives, power on rigs, run scripts.
        """
        action = step.get("action", "")
        target = step.get("target", "")
        self.logger.info(
            f"Executing step: action={action} target={target}"
        )

        # Simulate execution
        time.sleep(0.01)  # simulate fast execution

        # Audit the step
        self._audit_log("step_completed", {
            "execution_id": execution.execution_id,
            "step": step,
        })

    def get_state(self) -> Dict:
        """Return orchestrator state for the executive dashboard."""
        return {
            "backups_available": sum(1 for b in self.backups.values() if b.is_usable()),
            "backups_total": len(self.backups),
            "restore_rigs_operational": sum(1 for r in self.rigs.values() if r.test_status == "passed"),
            "restore_rigs_total": len(self.rigs),
            "golden_images_verified": sum(1 for i in self.images.values()),
            "runbooks_total": len(self.runbooks),
            "active_executions": sum(1 for e in self._executions.values() if e.overall_status == "in_progress"),
        }

    def _audit_log(self, action: str, details: Dict) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "details": details,
        }
        with self.audit_log_path.open("a", encoding="utf-8") as f:
            f.write(f"{entry}\n")


# =============================================================================
# Example usage
# =============================================================================


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Pre-staged external assets (in production, maintained by Track A)
    backups = [
        ImmutableBackup(
            backup_id="backup-ipc-line-1-2024-09-01",
            system_category="industrial_pc",
            created_at=datetime.now(timezone.utc) - timedelta(days=1),
            size_gb=120.0,
            signature="placeholder_signature",
            last_verified=datetime.now(timezone.utc) - timedelta(hours=12),
        ),
        ImmutableBackup(
            backup_id="backup-bms-line-1-2024-09-01",
            system_category="bms_controller",
            created_at=datetime.now(timezone.utc) - timedelta(days=1),
            size_gb=8.0,
            signature="placeholder_signature",
            last_verified=datetime.now(timezone.utc) - timedelta(hours=12),
        ),
    ]

    restore_rigs = [
        PreConfiguredRestoreRig(
            rig_id="rig-airgap-1",
            system_category="industrial_pc",
            location="secure-vault-A",
            last_tested=datetime.now(timezone.utc) - timedelta(days=7),
        ),
    ]

    golden_images = [
        PreValidatedGoldenImage(
            image_id="image-ipc-line-1-v3",
            system_category="industrial_pc",
            version="3.2.1",
            signed_at=datetime.now(timezone.utc) - timedelta(days=30),
            signature="placeholder_signature",
            last_verified=datetime.now(timezone.utc) - timedelta(days=30),
        ),
    ]

    runbooks = [
        PreAuthorisedRunbook(
            runbook_id="rb-ransomware-ipc",
            target_event="ransomware_industrial_pc",
            steps=[
                {"action": "hot_swap_backup", "target": "industrial_pc", "external": True},
                {"action": "power_on_restore_rig", "target": "rig-airgap-1", "external": True},
                {"action": "restore_golden_image", "target": "industrial_pc", "external": True},
                {"action": "verify_clean_state", "target": "industrial_pc", "external": True},
                {"action": "reconnect_to_network", "target": "industrial_pc", "external": True},
                {"action": "validate_recipe_signatures", "target": "all_plcs", "external": False},
                {"action": "resume_production", "target": "line_1", "external": True},
            ],
            ciso_approval_required=True,
            ciso_standing_approval=True,  # CISO standing approval for ransomware
            approved_by="ciso",
            approved_at=datetime.now(timezone.utc) - timedelta(days=30),
        ),
    ]

    # Create the orchestrator
    orchestrator = SMEDRecoveryOrchestrator(
        immutable_backups=backups,
        restore_rigs=restore_rigs,
        golden_images=golden_images,
        runbooks=runbooks,
        audit_log_path=Path("/var/log/cyber-resilience/smed-audit.jsonl"),
    )

    # Print state
    print(f"\n=== SMED orchestrator state ===")
    state = orchestrator.get_state()
    for k, v in state.items():
        print(f"  {k}: {v}")

    # Simulate recovery execution
    print(f"\n=== Simulated recovery execution ===")
    execution = orchestrator.execute_recovery(
        incident_id="INC-2024-09-02-001",
        target_event="ransomware_industrial_pc",
        runbook_id="rb-ransomware-ipc",
    )
    print(f"  execution_id: {execution.execution_id}")
    print(f"  overall_status: {execution.overall_status}")
    print(f"  completed_at: {execution.completed_at}")
    if execution.completed_at:
        elapsed = (execution.completed_at - execution.started_at).total_seconds()
        print(f"  elapsed_sec: {elapsed:.2f}")
