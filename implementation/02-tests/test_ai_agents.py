"""
Tests for the 4 AI agents (SOC Triage, OT Anomaly, IR Automation, Threat Intel).

Six Sigma quality bar: 100% pass on safety-critical tests.
Run with: python -m pytest 02-tests/test_ai_agents.py -v
"""

import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "01-reference-implementations" / "ai-agents"))

from base import (
    AgentConfig,
    AgentDecision,
    AlertEvent,
    AuditLog,
    DataLakeClient,
    QueryResult,
)
from soc_triage import SOCTriageAgent, KNOWN_SIGNATURES
from ot_anomaly import OTAnomalyDetectionAgent, SignedBaseline
from ir_automation import IRAutomationAgent, DEFAULT_PLAYBOOKS
from threat_intel import ThreatIntelCorrelationAgent


# =============================================================================
# Mocks
# =============================================================================


class MockDataLake(DataLakeClient):
    """Mock data lake for testing."""

    def __init__(self, rows: List[Dict[str, Any]] = None):
        self.rows = rows or []
        self.query_count = 0

    def query(self, sql, params=None, max_rows=10000, timeout_sec=30):
        self.query_count += 1
        return QueryResult(
            rows=self.rows[:max_rows],
            row_count=len(self.rows),
            query_id=f"mock-{self.query_count}",
            elapsed_ms=1,
        )


# =============================================================================
# SOC Triage tests
# =============================================================================


@pytest.fixture
def soc_triage(tmp_path):
    config = AgentConfig(
        agent_id="soc_triage",
        description="SOC Triage",
        fmea_modes_addressed=list(range(1, 13)),
        mttd_target_sec=120,
        mttr_target_sec=0,
        false_positive_rate_max=0.05,
        true_positive_rate_min=0.995,
        kill_switch_path=tmp_path / "kill.json",
        audit_log_path=tmp_path / "audit.jsonl",
    )
    return SOCTriageAgent(config, MockDataLake(), AuditLog(tmp_path / "audit.jsonl"))


class TestSOCTriage:
    def test_high_severity_routes_to_tier3(self, soc_triage):
        alert = AlertEvent(
            alert_id="alert-1",
            timestamp=datetime.now(timezone.utc),
            severity=10,
            description="Ransomware file extension detected: foo.locked",
            fmea_mode=9,
        )
        decision = soc_triage.process_alert(alert)
        assert decision.classification == "true_positive"
        assert decision.routing == "escalate_tier_3"
        assert decision.confidence > 0.85

    def test_ot_protocol_anomaly_routes_to_tier3(self, soc_triage):
        alert = AlertEvent(
            alert_id="alert-2",
            timestamp=datetime.now(timezone.utc),
            severity=9,
            description="modbus_write_unauth detected on safety-critical PLC",
            fmea_mode=10,
        )
        decision = soc_triage.process_alert(alert)
        assert decision.classification == "true_positive"
        assert decision.routing == "escalate_tier_3"

    def test_kill_switch_routes_to_tier2(self, soc_triage):
        soc_triage.kill("testing kill switch", "ciso_test")
        alert = AlertEvent(
            alert_id="alert-3",
            timestamp=datetime.now(timezone.utc),
            severity=10,
            description="test alert",
        )
        decision = soc_triage.process_alert(alert)
        # When killed, all alerts route to human review (Tier 2)
        assert decision.routing == "escalate_tier_2"
        assert "killed" in decision.reasoning.lower()

    def test_low_severity_auto_closes(self, soc_triage):
        alert = AlertEvent(
            alert_id="alert-4",
            timestamp=datetime.now(timezone.utc),
            severity=3,
            description="benign network event",
        )
        decision = soc_triage.process_alert(alert)
        # Low severity + few signals = likely false positive
        assert decision.classification == "false_positive"
        assert decision.routing == "auto_close"

    def test_revive_after_kill(self, soc_triage):
        soc_triage.kill("test", "ciso_test")
        soc_triage.revive("test complete", "ciso_test")
        assert not soc_triage.is_killed()

    def test_known_signatures_loaded(self):
        assert len(KNOWN_SIGNATURES) >= 4
        assert "ransomware_file_extension" in KNOWN_SIGNATURES
        assert "ot_protocol_anomaly" in KNOWN_SIGNATURES


# =============================================================================
# OT Anomaly Detection tests
# =============================================================================


@pytest.fixture
def ot_anomaly(tmp_path):
    config = AgentConfig(
        agent_id="ot_anomaly",
        description="OT Anomaly",
        fmea_modes_addressed=[1, 2, 3, 4, 5, 6, 7],
        mttd_target_sec=600,
        mttr_target_sec=0,
        false_positive_rate_max=0.03,
        true_positive_rate_min=0.999,
        kill_switch_path=tmp_path / "kill.json",
        audit_log_path=tmp_path / "audit.jsonl",
    )
    return OTAnomalyDetectionAgent(config, MockDataLake(), AuditLog(tmp_path / "audit.jsonl"))


class TestOTAnomaly:
    def test_drift_thresholds(self, ot_anomaly):
        """Drift thresholds should be set per Six Sigma targets."""
        assert ot_anomaly.DRIFT_THRESHOLDS["monitor"] == 1.0
        assert ot_anomaly.DRIFT_THRESHOLDS["tier_1"] == 5.0
        assert ot_anomaly.DRIFT_THRESHOLDS["tier_2"] == 10.0

    def test_baseline_within_tolerance(self):
        baseline = SignedBaseline(
            process_step="formation",
            parameter_name="charging_voltage",
            expected_value=4.2,
            tolerance_pct=2.0,
            signed_at=datetime.now(timezone.utc),
            signature="sig",
            signing_key_id="hsm-1",
        )
        within, dev = baseline.is_within_tolerance(4.20)
        assert within
        assert dev == 0.0

    def test_health_check(self, ot_anomaly):
        health = ot_anomaly.health()
        assert health["agent_id"] == "ot_anomaly"
        assert health["enabled"] is True
        assert 1 in health["fmea_modes_addressed"]  # SC modes


# =============================================================================
# IR Automation tests
# =============================================================================


@pytest.fixture
def ir_automation(tmp_path):
    config = AgentConfig(
        agent_id="ir_automation",
        description="IR Automation",
        fmea_modes_addressed=[8, 9, 10, 11, 12],
        mttd_target_sec=0,
        mttr_target_sec=3600,
        false_positive_rate_max=0.0,
        true_positive_rate_min=1.0,
        kill_switch_path=tmp_path / "kill.json",
        audit_log_path=tmp_path / "audit.jsonl",
    )
    return IRAutomationAgent(config, MockDataLake(), AuditLog(tmp_path / "audit.jsonl"))


class TestIRAutomation:
    def test_ransomware_playbook_loaded(self):
        assert "ransomware_industrial_pc" in DEFAULT_PLAYBOOKS

    def test_electrolyte_playbook_safety_critical(self):
        # Electrolyte is safety-critical — should have faster execution time
        playbook = DEFAULT_PLAYBOOKS["electrolyte_dosing_tampering"]
        assert playbook.max_execution_sec <= 1800  # ≤ 30 min

    def test_formation_charging_playbook(self):
        playbook = DEFAULT_PLAYBOOKS["formation_charging_tampering"]
        assert playbook.max_execution_sec <= 3600  # ≤ 1 hour

    def test_playbook_execution_logged(self, ir_automation, tmp_path):
        # Execute a ransomware playbook
        alert = AlertEvent(
            alert_id="incident-1",
            timestamp=datetime.now(timezone.utc),
            severity=10,
            description="ransomware file extension detected",
            fmea_mode=9,
            raw_signals={"target_event": "ransomware_industrial_pc"},
        )
        decision = ir_automation.process_alert(alert)
        # Playbook should have been selected
        assert decision.routing in ["auto_execute", "escalate_tier_2"]
        # Audit log should exist
        assert Path(tmp_path / "audit.jsonl").exists()


# =============================================================================
# Threat Intel tests
# =============================================================================


@pytest.fixture
def threat_intel(tmp_path):
    config = AgentConfig(
        agent_id="threat_intel",
        description="Threat Intel",
        fmea_modes_addressed=list(range(1, 13)),
        mttd_target_sec=0,
        mttr_target_sec=0,
        false_positive_rate_max=0.10,
        true_positive_rate_min=0.90,
        kill_switch_path=tmp_path / "kill.json",
        audit_log_path=tmp_path / "audit.jsonl",
    )
    return ThreatIntelCorrelationAgent(config, MockDataLake(), AuditLog(tmp_path / "audit.jsonl"))


class TestThreatIntel:
    def test_cell_sector_high_relevance(self, threat_intel):
        alert = AlertEvent(
            alert_id="intel-1",
            timestamp=datetime.now(timezone.utc),
            severity=8,
            description="APT campaign targets EV cell manufacturing",
            fmea_mode=1,
            raw_signals={"target_sector": "EV cell manufacturing", "intel_id": "intel-001"},
        )
        decision = threat_intel.process_alert(alert)
        assert decision.classification == "true_positive"
        assert decision.routing == "escalate_tier_2"

    def test_unrelated_sector_low_relevance(self, threat_intel):
        alert = AlertEvent(
            alert_id="intel-2",
            timestamp=datetime.now(timezone.utc),
            severity=8,
            description="APT campaign targets retail sector",
            fmea_mode=1,
            raw_signals={"target_sector": "retail", "intel_id": "intel-002"},
        )
        decision = threat_intel.process_alert(alert)
        assert decision.classification == "false_positive"
        assert decision.routing == "auto_close"


# =============================================================================
# Cross-agent tests
# =============================================================================


class TestCrossAgent:
    """Tests that span multiple agents."""

    def test_kill_switch_works_on_all_agents(self, tmp_path):
        """All 4 agents should support kill switch."""
        from soc_triage import make_soc_triage
        from ot_anomaly import make_ot_anomaly
        from ir_automation import make_ir_automation
        from threat_intel import make_threat_intel

        data_lake = MockDataLake()
        audit = AuditLog(tmp_path / "audit.jsonl")

        agents = [
            make_soc_triage(data_lake, audit),
            make_ot_anomaly(data_lake, audit),
            make_ir_automation(data_lake, audit),
            make_threat_intel(data_lake, audit),
        ]

        for agent in agents:
            # Each agent should support kill
            assert hasattr(agent, "kill")
            assert hasattr(agent, "revive")
            assert hasattr(agent, "is_killed")

            agent.kill("test", "ciso_test")
            assert agent.is_killed()

            agent.revive("test complete", "ciso_test")
            assert not agent.is_killed()
