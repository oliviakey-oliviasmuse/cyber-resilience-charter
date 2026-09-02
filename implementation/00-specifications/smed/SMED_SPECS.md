# SMED for Disaster Recovery Specifications

The SMED (Single-Minute Exchange of Die) repurposed from manufacturing changeover to cyber recovery. The principle: convert "internal" recovery steps (performed during the attack, under time pressure) into "external" steps (pre-staged, ready to deploy). MTTR target: ≤ 1 hour for hard stops.

## Charter reference

Charter reference: #4.5.4 of the charter.

## External (pre-staged) recovery assets

All assets must be:
- Cryptographically signed
- Verified monthly
- Stored in air-gapped or physically secured locations
- Ready to deploy without preparation

### 1. Immutable backups

**Interface:**
```
ImmutableBackup.verify() -> bool
ImmutableBackup.is_usable() -> bool
```

**Specification:**
- Storage: Write-Once-Read-Many (WORM) media
- Encryption: AES-256 or equivalent
- Cryptographic signature: Ed25519 from Track A's HSM
- Verification cadence: monthly, automated, audit-logged
- Refresh cadence: weekly (or after any material change)
- Retention: 7 years minimum
- Storage location: air-gapped, offsite (different physical location from production)
- Restoration test: monthly (SMED recovery verification routine)

**Properties:**
- Immutable: cannot be modified or deleted (WORM enforcement)
- Signed: tampering is detectable
- Verified: restoration is tested monthly
- Available: ready to hot-swap in < 5 minutes

### 2. Pre-configured restore rigs

**Interface:**
```
PreConfiguredRestoreRig.test() -> bool
```

**Specification:**
- Hardware: dedicated physical server, air-gapped
- Software: all necessary OS, runtime, dependencies pre-installed
- Configuration: matches production system configuration exactly
- Cryptographic verification: golden image signed and verified
- Test cadence: weekly (full restore test)
- Physical security: locked cabinet, access-controlled, audit-logged
- Failover: 3 rigs per critical system category (industrial PC, BMS, SCADA, etc.)

**Properties:**
- Pre-configured: zero setup time during recovery
- Tested: weekly full restore validates the rig
- Signed: rig's golden image is verified against Track A's signing service
- Available: ready to power on in < 1 minute

### 3. Pre-validated golden images

**Interface:**
```
PreValidatedGoldenImage.verify_signature() -> bool
```

**Specification:**
- Image format: signed, immutable, versioned
- Signature: Ed25519 from Track A's HSM
- Validation: monthly automated verification
- Versions: each golden image has a version number; rollback to older versions is prohibited (security)
- Storage: offline, cryptographically sealed
- Refresh: on every material change to the production system

**Properties:**
- Signed: signature prevents tampering
- Validated: monthly verification
- Versioned: explicit version control, no silent rollback
- Available: ready to deploy from the restore rig

### 4. Pre-authorised runbooks

**Interface:**
```
PreAuthorisedRunbook.execute(incident_id: str) -> RecoveryExecution
```

**Specification:**
- CISO standing approval: at G1, the CISO pre-authorises runbooks for Severity ≥ 8 events
- Per-incident CISO approval: for runbooks WITHOUT standing approval, the orchestrator escalates to CISO before executing
- Runbook contents:
  - Target event (ransomware, OT compromise, safety event, etc.)
  - Pre-staged assets used (backup ID, restore rig ID, golden image ID)
  - Step-by-step actions with timeouts
  - CISO notification triggers and SLAs
  - Clean-state validation requirements
- Audit trail: every step is logged with timestamp, action, result
- Maximum execution time: enforced by `max_execution_sec` per playbook

**Properties:**
- Pre-authorised: no per-incident approval needed for Severity ≥ 8
- Auditable: every step is logged
- Bounded: maximum execution time enforced
- Reversible: all actions can be rolled back (with CISO approval)

## Internal (during the attack) recovery actions

These actions must be MINIMISED. Every internal action takes time during the attack. The SMED principle: convert as many as possible to external.

| Step | External (pre-staged) | Internal (during attack) |
|---|---|---|
| Find backup files | Hot-swappable drive, indexed by backup ID | — |
| Configure recovery server | Pre-built restore rig | — |
| Validate recovered systems | Pre-validated golden image | — |
| Authorise recovery actions | Pre-authorised runbook (CISO standing approval for Severity ≥ 8) | Per-incident CISO approval (if no standing approval) |
| Reconnect to network | — | Yes, only after clean-state validation |

## Reference implementation

`01-reference-implementations/smed/recovery_rig.py`:
- `ImmutableBackup` dataclass
- `PreConfiguredRestoreRig` dataclass
- `PreValidatedGoldenImage` dataclass
- `PreAuthorisedRunbook` dataclass
- `SMEDRecoveryOrchestrator` class with `execute_recovery()` method
- Default playbooks for ransomware, formation charging tampering, electrolyte dosing tampering

## Default playbooks

### Ransomware on Industrial PC

- **Trigger:** SOC Triage detects ransomware_file_extension signature
- **Steps:** isolate_segment → snapshot_forensic_state → activate_smed_recovery → notify_ciso
- **Max execution time:** 1 hour (3,600 seconds)
- **CISO standing approval:** YES (CISO pre-authorised at G1 for ransomware on industrial PCs)
- **CISO notification SLA:** 15 minutes

### Formation charging profile tampering

- **Trigger:** OT Anomaly detects deviation from signed recipe
- **Steps:** isolate_formation_line → snapshot_bms_state → revert_to_signed_recipe → verify_cell_parameters → notify_ciso_and_safety
- **Max execution time:** 1 hour
- **CISO standing approval:** YES
- **CISO notification SLA:** 15 minutes

### Electrolyte dosing volume tampering (safety-critical)

- **Trigger:** OT Anomaly detects deviation from signed recipe
- **Steps:** isolate_electrolyte_line → engage_safety_interlocks → snapshot_hmi_state → notify_ciso_and_safety_immediate
- **Max execution time:** 30 minutes (1,800 seconds) — TIGHTER for safety
- **CISO standing approval:** YES
- **CISO notification SLA:** 1 minute (SAFETY-CRITICAL)

## Performance targets

- MTTR ≤ 1 hour for hard stops (ransomware, OT compromise)
- MTTR ≤ 30 minutes for safety-critical events (electrolyte dosing, formation charging)
- CISO notification within 15 minutes for hard stops
- CISO notification within 1 minute for safety-critical
- All actions idempotent (safe to retry)
- All actions reversible (with CISO approval)
- All actions audited (every step logged)

## Deployment

- Track C (Automation) owns the SMED orchestrator
- Track A (Architecture) maintains the pre-staged assets
- CISO approves runbooks at G1 (standing approval for Severity ≥ 8)
- Tested in Weeks 8-10; validated in the G4 red-team exercise
- Monthly drill validation (Track C standard work)
- Quarterly full recovery drill

## Failure modes

| Failure | Response |
|---|---|
| Backup unavailable | Use secondary backup; if all backups fail, escalate to Tier 3 |
| Restore rig fails | Use secondary rig (3 rigs per critical system) |
| Golden image fails verification | Use previous verified image; if all fail, escalate to Tier 3 |
| Runbook step fails | Pause execution; escalate to Tier 3 for human IR |
| CISO unreachable for safety-critical event | Pre-authorised runbook executes; CISO delegate authorised for notification |
| SMED exceeds max_execution_sec | Escalate to Tier 3 immediately |

## Six Sigma alignment

The SMED recovery supports the engagement-level target of Z ≥ 6.0 (MTTR ≤ 1 hour):

- Pre-staging eliminates time-consuming steps (search, configure, validate)
- Pre-authorisation eliminates approval latency for Severity ≥ 8
- Hot-swap assets eliminate setup time
- Auditable execution enables continuous improvement

**Target:** ≥ 95% of incidents recovered within MTTR target (Cpk ≥ 1.5, Z ≥ 4.5 for SMED itself; combined with other controls, engagement-level Z ≥ 6.0).
