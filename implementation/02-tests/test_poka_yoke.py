"""
Tests for Cyber Poka-Yoke enforcement (parameter drift interlock + recipe signer).

Six Sigma quality bar: 100% pass required on safety-critical tests.
Run with: python -m pytest 02-tests/test_poka_yoke.py -v
"""

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Add reference implementations to path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "01-reference-implementations" / "poka-yoke"))
sys.path.insert(0, str(ROOT / "01-reference-implementations" / "ai-agents"))

from parameter_drift_interlock import (
    ParameterDriftInterlock,
    SignedBaseline,
    BaselineTamperedError,
    LineState,
)


@pytest.fixture
def baseline():
    """A valid signed baseline for testing."""
    return SignedBaseline(
        process_step="formation",
        parameter_name="charging_voltage",
        expected_value=4.2,
        tolerance_pct=2.0,
        signed_at=datetime.now(timezone.utc),
        signature="valid_signature_placeholder",
        signing_key_id="hsm-key-formation-2024",
    )


@pytest.fixture
def interlock(baseline, tmp_path):
    """A parameter drift interlock with the valid baseline."""
    return ParameterDriftInterlock(
        process_step="formation",
        baseline=baseline,
        audit_log_path=tmp_path / "interlock-audit.jsonl",
    )


# =============================================================================
# Signed baseline tests
# =============================================================================


class TestSignedBaseline:
    def test_within_tolerance(self, baseline):
        within, dev = baseline.is_within_tolerance(4.20)
        assert within
        assert dev == 0.0

    def test_within_tolerance_small_drift(self, baseline):
        # 1% drift
        within, dev = baseline.is_within_tolerance(4.242)  # 4.2 * 1.01
        assert within
        assert abs(dev - 1.0) < 0.01

    def test_outside_tolerance(self, baseline):
        # 5% drift
        within, dev = baseline.is_within_tolerance(4.41)  # 4.2 * 1.05
        assert not within
        assert abs(dev - 5.0) < 0.01

    def test_zero_expected_value(self, baseline):
        baseline.expected_value = 0
        within, dev = baseline.is_within_tolerance(0)
        assert within
        assert dev == 0.0
        within, dev = baseline.is_within_tolerance(0.001)
        assert not within


# =============================================================================
# Interlock tests
# =============================================================================


class TestParameterDriftInterlock:
    def test_signature_verification_passes(self, baseline, tmp_path):
        # Should not raise
        interlock = ParameterDriftInterlock(
            process_step="formation",
            baseline=baseline,
            audit_log_path=tmp_path / "audit.jsonl",
        )
        assert interlock._state == LineState.RUNNING

    def test_empty_signature_raises(self, baseline, tmp_path):
        baseline.signature = ""
        with pytest.raises(BaselineTamperedError):
            ParameterDriftInterlock(
                process_step="formation",
                baseline=baseline,
                audit_log_path=tmp_path / "audit.jsonl",
            )

    def test_within_tolerance_no_isolation(self, interlock):
        event = interlock.check_parameter(4.20)
        assert event.action_taken == "log_only"
        assert interlock._state == LineState.RUNNING

    def test_drift_triggers_isolation(self, interlock):
        # 5% drift → exceeds 2% tolerance
        event = interlock.check_parameter(4.41)
        assert event.action_taken == "isolate_line"
        assert interlock._state == LineState.ISOLATED

    def test_isolation_count_increments(self, interlock):
        # First isolation
        interlock.check_parameter(4.41)
        assert interlock._isolation_count == 1
        # Second parameter check (already isolated, should skip)
        interlock.check_parameter(4.50)
        assert interlock._isolation_count == 1  # No duplicate

    def test_audit_log_written_on_isolation(self, interlock):
        interlock.check_parameter(4.41)  # 5% drift
        assert interlock.audit_log_path.exists()
        content = interlock.audit_log_path.read_text()
        assert "LINE_ISOLATED" in content
        assert "formation" in content
        assert "4.41" in content

    def test_fail_closed_on_check_error(self, interlock, baseline, monkeypatch):
        # Simulate a check failure
        def broken_check(observed):
            raise RuntimeError("Simulated monitoring failure")

        monkeypatch.setattr(baseline, "is_within_tolerance", broken_check)
        event = interlock.check_parameter(4.20)
        # Should fail closed (isolate)
        assert event.action_taken == "isolate_line"
        assert interlock._state == LineState.ISOLATED

    def test_get_state(self, interlock):
        state = interlock.get_state()
        assert state["process_step"] == "formation"
        assert state["state"] == "running"
        assert state["isolation_count"] == 0
        assert state["baseline_expected"] == 4.2
        assert state["baseline_tolerance_pct"] == 2.0


# =============================================================================
# Six Sigma performance tests
# =============================================================================


class TestPerformance:
    def test_check_latency_under_1_second(self, interlock):
        """Each check should complete in < 1 second (for real-time monitoring)."""
        start = time.time()
        for _ in range(1000):
            interlock.check_parameter(4.20)
        elapsed = time.time() - start
        per_check = elapsed / 1000
        assert per_check < 0.001, f"Check latency {per_check*1000:.2f}ms exceeds 1ms target"
