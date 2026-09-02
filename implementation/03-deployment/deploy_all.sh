#!/bin/bash
# Cyber Resilience — Phase 4 (Improve) Deployment Script
# Deploys the 4 AI agents, Poka-Yoke enforcers, SMED recovery rig, and dashboard.
# Six Sigma-aligned (Z ≥ 6.0 target).
#
# Usage: ./deploy_all.sh [--dry-run] [--track=architecture|data|automation]
#
# Requires:
# - Python 3.11+
# - CISO team has provisioned the anonymised data lake
# - Track A has deployed the cryptographic signing infrastructure (HSM)
# - All secrets (HSM keys, data lake credentials) are in the secret manager

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMPL_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="/var/log/cyber-resilience"
CONFIG_DIR="/etc/cyber-resilience"

# Parse arguments
DRY_RUN=false
TRACK=""
for arg in "$@"; do
    case $arg in
        --dry-run) DRY_RUN=true ;;
        --track=*) TRACK="${arg#*=}" ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# Logging
mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_DIR/deploy-$(date +%Y%m%d-%H%M%S).log") 2>&1

echo "=================================================="
echo "Cyber Resilience — Phase 4 (Improve) Deployment"
echo "Started: $(date)"
echo "Dry run: $DRY_RUN"
echo "Track filter: ${TRACK:-all}"
echo "=================================================="

# Step 0: Pre-flight checks
echo ""
echo "=== Pre-flight checks ==="

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "ERROR: $1 not found"
        exit 1
    fi
    echo "  ✓ $1"
}

check_command python3
check_command pip3
check_command pytest
check_command systemctl

# Check CISO data lake access
if [ ! -f "$CONFIG_DIR/data-lake-credentials" ]; then
    echo "ERROR: Data lake credentials not found at $CONFIG_DIR/data-lake-credentials"
    echo "       The CISO team must provision this BEFORE deployment"
    exit 1
fi
echo "  ✓ Data lake credentials present"

# Check HSM access (Track A)
if [ ! -f "$CONFIG_DIR/hsm-credentials" ]; then
    echo "ERROR: HSM credentials not found at $CONFIG_DIR/hsm-credentials"
    echo "       Track A's signing infrastructure must be deployed first"
    exit 1
fi
echo "  ✓ HSM credentials present"

# Step 1: Install Python dependencies
echo ""
echo "=== Installing Python dependencies ==="
pip3 install --quiet -r "$IMPL_ROOT/03-deployment/requirements.txt"
echo "  ✓ Python dependencies installed"

# Step 2: Run tests
echo ""
echo "=== Running test suite ==="
cd "$IMPL_ROOT"
python3 -m pytest 02-tests/ -v --tb=short
echo "  ✓ All tests passed"

# Step 3: Deploy Track A (Architecture — Poka-Yoke + DMZ)
if [ -z "$TRACK" ] || [ "$TRACK" = "architecture" ]; then
    echo ""
    echo "=== Deploying Track A (Architecture) ==="

    # Poka-Yoke enforcement
    if [ "$DRY_RUN" = false ]; then
        # Deploy parameter drift interlock as systemd service
        cat > /etc/systemd/system/cyber-poka-yoke.service <<EOF
[Unit]
Description=Cyber Resilience - Parameter Drift Interlock
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $IMPL_ROOT/01-reference-implementations/poka-yoke/parameter_drift_interlock.py
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable cyber-poka-yoke.service
        systemctl start cyber-poka-yoke.service
        echo "  ✓ Parameter drift interlock deployed"
    else
        echo "  [DRY RUN] Would deploy parameter drift interlock"
    fi

    # Cryptographic recipe signer (Track A maintains the HSM; this is the verification side)
    if [ "$DRY_RUN" = false ]; then
        cat > /etc/systemd/system/cyber-recipe-verifier.service <<EOF
[Unit]
Description=Cyber Resilience - Recipe Signature Verifier
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $IMPL_ROOT/01-reference-implementations/poka-yoke/cryptographic_recipe_signer.py
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable cyber-recipe-verifier.service
        systemctl start cyber-recipe-verifier.service
        echo "  ✓ Recipe verifier deployed"
    fi
fi

# Step 4: Deploy Track B (Data & Metrics)
if [ -z "$TRACK" ] || [ "$TRACK" = "data" ]; then
    echo ""
    echo "=== Deploying Track B (Data & Metrics) ==="

    if [ "$DRY_RUN" = false ]; then
        # Data lake query interface
        cat > /etc/systemd/system/cyber-data-lake.service <<EOF
[Unit]
Description=Cyber Resilience - Anonymised Data Lake Query Interface
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $IMPL_ROOT/01-reference-implementations/data-lake/query_interface.py
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable cyber-data-lake.service
        systemctl start cyber-data-lake.service
        echo "  ✓ Anonymised data lake query interface deployed"
    fi
fi

# Step 5: Deploy Track C (Automation — 4 AI agents + SMED)
if [ -z "$TRACK" ] || [ "$TRACK" = "automation" ]; then
    echo ""
    echo "=== Deploying Track C (Automation) ==="

    for agent in soc_triage ot_anomaly ir_automation threat_intel; do
        if [ "$DRY_RUN" = false ]; then
            cat > /etc/systemd/system/cyber-agent-${agent}.service <<EOF
[Unit]
Description=Cyber Resilience - AI Agent (${agent})
After=network.target cyber-data-lake.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $IMPL_ROOT/01-reference-implementations/ai-agents/${agent}.py
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable cyber-agent-${agent}.service
            systemctl start cyber-agent-${agent}.service
            echo "  ✓ ${agent} agent deployed"
        fi
    done

    # SMED recovery orchestrator
    if [ "$DRY_RUN" = false ]; then
        cat > /etc/systemd/system/cyber-smed.service <<EOF
[Unit]
Description=Cyber Resilience - SMED Recovery Orchestrator
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $IMPL_ROOT/01-reference-implementations/smed/recovery_rig.py
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable cyber-smed.service
        systemctl start cyber-smed.service
        echo "  ✓ SMED recovery orchestrator deployed"
    fi
fi

# Step 6: Post-deployment verification
echo ""
echo "=== Post-deployment verification ==="

if [ "$DRY_RUN" = false ]; then
    # Check all services are running
    for service in cyber-poka-yoke cyber-recipe-verifier cyber-data-lake cyber-smed \
                  cyber-agent-soc_triage cyber-agent-ot_anomaly \
                  cyber-agent-ir_automation cyber-agent-threat_intel; do
        if systemctl is-active --quiet "$service"; then
            echo "  ✓ $service running"
        else
            echo "  ✗ $service NOT running"
        fi
    done

    # Run a quick health check
    echo ""
    echo "=== Health check ==="
    cd "$IMPL_ROOT"
    python3 -c "
from pathlib import Path
import sys
sys.path.insert(0, '01-reference-implementations/data-lake')
sys.path.insert(0, '01-reference-implementations/ai-agents')
from query_interface import AnonymisedDataLake
from soc_triage import make_soc_triage
from ot_anomaly import make_ot_anomaly
from ir_automation import make_ir_automation
from threat_intel import make_threat_intel
from base import AuditLog

data_lake = AnonymisedDataLake(audit_log_path=Path('/var/log/cyber-resilience/data-lake-audit.jsonl'))
audit = AuditLog(Path('/var/log/cyber-resilience/audit.jsonl'))
agents = [make_soc_triage(data_lake, audit), make_ot_anomaly(data_lake, audit), make_ir_automation(data_lake, audit), make_threat_intel(data_lake, audit)]
for a in agents:
    print(f'  {a.config.agent_id}: enabled={not a.is_killed()}, fmea_modes={a.config.fmea_modes_addressed}')
"
fi

echo ""
echo "=================================================="
echo "Deployment complete: $(date)"
echo "Audit log: $LOG_DIR"
echo "Configuration: $CONFIG_DIR"
echo "=================================================="
