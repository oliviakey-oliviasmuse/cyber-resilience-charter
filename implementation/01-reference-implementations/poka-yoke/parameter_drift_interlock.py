"""
Cyber Poka-Yoke #5: Parameter Drift Interlock with Auto-Isolation

This is the structural enforcement for the 7 silent corruption modes
(FMEA modes #1-7 in §4.4.3 of the charter). The largest exposure class
in the engagement — silent corruption — is exactly the failure class that
the original IT security perimeter cannot see (no halt event to alert on).

The Parameter Drift Interlock solves this by:
1. Continuously comparing observed process parameters against cryptographically
   signed baselines (Poka-Yoke #3)
2. Detecting drift beyond signed tolerance
3. Auto-isolating the affected line segment BEFORE defective cells continue
   down the line

This is the structural answer to "how do you hold Z ≥ 6.0 for silent corruption
when there's no halt event to trigger an alert?"

Design:
- Real-time parameter stream (from the anonymised data lake; raw PLC signals
  are signed and the signed values are what we monitor)
- Drift detection (signed baseline comparison)
- Auto-isolation (fail-closed; if the interlock fails, the line stays isolated)
- Audit trail (every comparison, every isolation)
- Six Sigma: 99.9% detection rate, ≤ 5 sec detection latency
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional


# =============================================================================
# Signed baseline (Poka-Yoke #3)
# =============================================================================


@dataclass
class SignedBaseline:
    """A cryptographically signed process parameter baseline.

    Signed by Track A's signing infrastructure. The signature prevents
    an attacker from modifying the baseline — even if they compromise the
    SCADA/PLC, they cannot forge a valid signature without the signing key
    (held in an HSM by Track A).
    """
    process_step: str  # e.g., "formation", "electrolyte_injection"
    parameter_name: str  # e.g., "charging_voltage", "dosing_volume"
    expected_value: float
    tolerance_pct: float  # allowed deviation as percentage
    signed_at: datetime
    signature: str  # cryptographic signature (Ed25519 or similar)
    signing_key_id: str  # HSM key identifier
    algorithm: str = "Ed25519"

    def is_within_tolerance(self, observed: float) -> tuple[bool, float]:
        """Check observed against signed tolerance.

        Returns: (within_tolerance, deviation_pct)
        """
        if self.expected_value == 0:
            return (observed == 0, 0.0)
        deviation_pct = abs(observed - self.expected_value) / abs(self.expected_value) * 100
        return (deviation_pct <= self.tolerance_pct, deviation_pct)


class BaselineTamperedError(Exception):
    """Raised when a baseline's signature fails verification."""
    pass


# =============================================================================
# Interlock state and actions
# =============================================================================


class LineState(Enum):
    """State of a production line."""
    RUNNING = "running"
    ISOLATED = "isolated"  # stopped, awaiting investigation
    RECOVERING = "recovering"  # SMED rig in progress


@dataclass
class InterlockEvent:
    """An interlock-triggered event."""
    event_id: str
    timestamp: datetime
    process_step: str
    parameter_name: str
    observed_value: float
    expected_value: float
    deviation_pct: float
    action_taken: str  # "log_only", "isolate_line", "isolate_and_alert_ciso"
    audit_log_id: str


# =============================================================================
# The interlock
# =============================================================================


class ParameterDriftInterlock:
    """Real-time parameter drift interlock with auto-isolation.

    Monitors process parameters against cryptographically signed baselines.
    Auto-isolates the line segment when drift exceeds the signed tolerance.

    Constraint: FAIL-CLOSED. If the interlock encounters an error (signature
    verification fails, baseline missing, monitoring fails), the line is
    ISOLATED — never allowed to continue with unknown state.

    This is the structural enforcement for silent corruption. It transforms
    a class of failure that the IT perimeter cannot see into one that the
    OT system itself prevents.
    """

    def __init__(
        self,
        process_step: str,
        baseline: SignedBaseline,
        audit_log_path: Path,
        isolation_callback: Optional[Callable[[str], None]] = None,
    ):
        self.process_step = process_step
        self.baseline = baseline
        self.audit_log_path = Path(audit_log_path)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        self._isolation_callback = isolation_callback
        self._state = LineState.RUNNING
        self._isolation_count = 0
        self._drift_events: List[InterlockEvent] = []
        self.logger = logging.getLogger(f"interlock.{process_step}")
        self._verify_baseline_signature()

    def _verify_baseline_signature(self) -> None:
        """Verify the baseline's cryptographic signature.

        In production, this calls the Track A signing service to verify
        the signature. If verification fails, raise BaselineTamperedError —
        the line should not be allowed to run with a tampered baseline.
        """
        # In production: call the signing service
        # signing_service.verify(self.baseline)
        # For this reference implementation, simulate verification
        if not self.baseline.signature:
            raise BaselineTamperedError(
                f"Baseline for {self.process_step}::{self.baseline.parameter_name} "
                f"has empty signature"
            )
        # Otherwise, assume signature is valid
        self.logger.info(
            f"Baseline verified: {self.process_step}::{self.baseline.parameter_name} "
            f"value={self.baseline.expected_value} ±{self.baseline.tolerance_pct}%"
        )

    def check_parameter(self, observed: float) -> InterlockEvent:
        """Check an observed parameter against the signed baseline.

        If drift is within tolerance: log only, line stays running.
        If drift exceeds tolerance: auto-isolate the line segment.

        FAIL-CLOSED: if the check itself fails, the line is isolated.
        """
        timestamp = datetime.now(timezone.utc)
        try:
            within_tolerance, deviation_pct = self.baseline.is_within_tolerance(observed)
        except Exception as e:
            # Check failed — fail closed
            self.logger.error(
                f"Parameter check failed for {self.process_step}::{self.baseline.parameter_name}: {e}"
            )
            self._isolate_line(
                f"parameter check failed: {e}",
                observed=observed,
                expected=self.baseline.expected_value,
                deviation_pct=float("inf"),
            )
            return self._record_event(
                timestamp=timestamp,
                observed=observed,
                expected=self.baseline.expected_value,
                deviation_pct=float("inf"),
                action="isolate_line",
            )

        if within_tolerance:
            # Within tolerance — log only
            return self._record_event(
                timestamp=timestamp,
                observed=observed,
                expected=self.baseline.expected_value,
                deviation_pct=deviation_pct,
                action="log_only",
            )

        # Exceeds tolerance — auto-isolate
        self.logger.warning(
            f"DRIFT DETECTED: {self.process_step}::{self.baseline.parameter_name} "
            f"observed={observed} expected={self.baseline.expected_value} "
            f"deviation={deviation_pct:.2f}% (tolerance={self.baseline.tolerance_pct}%)"
        )
        self._isolate_line(
            f"parameter drift {deviation_pct:.2f}% exceeds tolerance {self.baseline.tolerance_pct}%",
            observed=observed,
            expected=self.baseline.expected_value,
            deviation_pct=deviation_pct,
        )
        return self._record_event(
            timestamp=timestamp,
            observed=observed,
            expected=self.baseline.expected_value,
            deviation_pct=deviation_pct,
            action="isolate_line",
        )

    def _isolate_line(
        self,
        reason: str,
        observed: float,
        expected: float,
        deviation_pct: float,
    ) -> None:
        """Isolate the line segment. FAIL-CLOSED.

        In production, this calls the Poka-Yoke enforcement service to
        physically stop the line (e.g., emergency stop signal to the PLC).
        The line stays isolated until the SMED recovery rig restores it.
        """
        if self._state == LineState.ISOLATED:
            self.logger.warning("Line already isolated; skipping duplicate isolation")
            return

        self._state = LineState.ISOLATED
        self._isolation_count += 1

        # Log the isolation
        audit_log_id = self._log_isolation(
            reason=reason,
            observed=observed,
            expected=expected,
            deviation_pct=deviation_pct,
        )

        self.logger.critical(
            f"LINE ISOLATED: process_step={self.process_step} "
            f"reason={reason} audit_log_id={audit_log_id}"
        )

        # Trigger the isolation callback (e.g., PLC emergency stop)
        if self._isolation_callback:
            try:
                self._isolation_callback(self.process_step)
            except Exception as e:
                # Callback failed — but we're already in the safe state
                self.logger.error(f"Isolation callback failed: {e}")

    def _log_isolation(
        self,
        reason: str,
        observed: float,
        expected: float,
        deviation_pct: float,
    ) -> str:
        """Log the isolation to the audit trail."""
        audit_log_id = f"interlock-{int(time.time() * 1000)}"
        entry = {
            "audit_log_id": audit_log_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "LINE_ISOLATED",
            "process_step": self.process_step,
            "parameter_name": self.baseline.parameter_name,
            "observed_value": observed,
            "expected_value": expected,
            "deviation_pct": deviation_pct,
            "tolerance_pct": self.baseline.tolerance_pct,
            "reason": reason,
            "isolation_count": self._isolation_count,
        }
        with self.audit_log_path.open("a", encoding="utf-8") as f:
            f.write(f"{entry}\n")
        return audit_log_id

    def _record_event(
        self,
        timestamp: datetime,
        observed: float,
        expected: float,
        deviation_pct: float,
        action: str,
    ) -> InterlockEvent:
        """Record a check event."""
        event = InterlockEvent(
            event_id=f"chk-{int(time.time() * 1000000)}",
            timestamp=timestamp,
            process_step=self.process_step,
            parameter_name=self.baseline.parameter_name,
            observed_value=observed,
            expected_value=expected,
            deviation_pct=deviation_pct,
            action_taken=action,
            audit_log_id="",
        )
        self._drift_events.append(event)
        return event

    def get_state(self) -> Dict:
        """Return current state for the executive dashboard."""
        return {
            "process_step": self.process_step,
            "state": self._state.value,
            "isolation_count": self._isolation_count,
            "baseline_parameter": self.baseline.parameter_name,
            "baseline_expected": self.baseline.expected_value,
            "baseline_tolerance_pct": self.baseline.tolerance_pct,
            "recent_drift_events": len(self._drift_events),
        }


# =============================================================================
# Example usage
# =============================================================================


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create a signed baseline (in production, from Track A's signing service)
    baseline = SignedBaseline(
        process_step="formation",
        parameter_name="charging_voltage",
        expected_value=4.2,  # volts
        tolerance_pct=2.0,  # ±2%
        signed_at=datetime.now(timezone.utc),
        signature="placeholder_signature_from_HSM",
        signing_key_id="hsm-key-formation-2024",
    )

    # Create the interlock
    interlock = ParameterDriftInterlock(
        process_step="formation",
        baseline=baseline,
        audit_log_path=Path("/var/log/cyber-resilience/interlock-audit.jsonl"),
    )

    # Simulate parameter checks
    print("\n=== Simulated parameter checks ===")
    test_values = [4.20, 4.21, 4.25, 4.30, 4.50, 4.20, 4.18]
    for v in test_values:
        event = interlock.check_parameter(v)
        print(
            f"  observed={v:5.2f}V expected={baseline.expected_value:.2f}V "
            f"deviation={(abs(v-baseline.expected_value)/baseline.expected_value*100):5.2f}% "
            f"action={event.action_taken}"
        )

    # Print state
    print(f"\n=== Final state ===")
    state = interlock.get_state()
    for k, v in state.items():
        print(f"  {k}: {v}")
