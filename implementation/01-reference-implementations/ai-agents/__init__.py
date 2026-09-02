"""
Cyber Resilience AI Agents — Layer 3 of the 4-layer OSI translation.

Four autonomous agents operating within the Data-Blind Protocol (#3.5 of the charter).
Each agent:
- Queries ONLY the anonymised data lake
- Has a CISO-controlled kill switch
- Logs every action to the audit trail
- Targets Six Sigma capability (Cpk ≥ 2.0, Z ≥ 6.0)
- Has bounded resource usage
- Has idempotent operations

Mapping to the FMEA:
- Agent 1 (SOC Triage): all 12 modes
- Agent 2 (OT Anomaly): 7 silent corruption modes (the binding risk class)
- Agent 3 (IR Automation): 5 hard stop modes
- Agent 4 (Threat Intel): all 12 modes (preventive)
"""

from .base import (
    AgentConfig,
    AgentDecision,
    AlertEvent,
    AuditLog,
    CyberAgent,
    DataAccessError,
    DataLakeClient,
    QueryResult,
    Severity,
    AgentKilledError,
)
from .soc_triage import SOCTriageAgent, make_default_agent as make_soc_triage
from .ot_anomaly import OTAnomalyDetectionAgent, make_default_agent as make_ot_anomaly
from .ir_automation import IRAutomationAgent, make_default_agent as make_ir_automation
from .threat_intel import ThreatIntelCorrelationAgent, make_default_agent as make_threat_intel


__all__ = [
    # Base
    "AgentConfig",
    "AgentDecision",
    "AlertEvent",
    "AuditLog",
    "CyberAgent",
    "DataAccessError",
    "DataLakeClient",
    "QueryResult",
    "Severity",
    "AgentKilledError",
    # Agents
    "SOCTriageAgent",
    "OTAnomalyDetectionAgent",
    "IRAutomationAgent",
    "ThreatIntelCorrelationAgent",
    # Factory functions
    "make_soc_triage",
    "make_ot_anomaly",
    "make_ir_automation",
    "make_threat_intel",
]


def make_all_agents(
    data_lake: DataLakeClient, audit: AuditLog
) -> Dict[str, CyberAgent]:
    """Construct all 4 agents with default configuration.

    Returns:
        Dictionary mapping agent_id to agent instance.
    """
    return {
        "soc_triage": make_soc_triage(data_lake, audit),
        "ot_anomaly": make_ot_anomaly(data_lake, audit),
        "ir_automation": make_ir_automation(data_lake, audit),
        "threat_intel": make_threat_intel(data_lake, audit),
    }
