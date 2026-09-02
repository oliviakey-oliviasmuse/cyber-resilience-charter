# Cyber Poka-Yoke Specifications

The 5 structural principles from §4.5.3 of the charter. Each principle is enforced as a security control, not a procedure.

## Principle 1: Hard-coded network isolation at PLC firmware level

**Charter reference:** §4.5.3 — "Critical line PLCs reject any inbound traffic that does not originate from a locally authenticated, cryptographic handshake."

### Interface

```
PLC_FIRMWARE.isolate(input_packet, peer_identity) -> Decision
```

### Specification

- PLC firmware must verify the cryptographic identity of every inbound packet
- Verification is done at the firmware level (not the OS level)
- Reject if identity cannot be verified cryptographically
- No "soft" rule that can be bypassed; this is hard-coded
- Identity verification uses Ed25519 signatures (consistent with the recipe signer)

### Properties

- **Fail-closed:** If verification fails, the packet is dropped. No exceptions.
- **Bypass-resistant:** Removing the firmware check requires physical access to the PLC and re-flashing.
- **Audit:** Every rejected packet is logged with timestamp, source, reason.

### Reference implementation

- `01-reference-implementations/poka-yoke/parameter_drift_interlock.py` (the parameter-drift interlock depends on this)
- In production: PLC firmware implementation (CODESYS, Beckhoff, Siemens, etc., per the actual OT environment)

### Deployment

- Track A (Architecture) owns the firmware specification
- Tested in Weeks 8-10 (Improve phase)
- Validated in the G4 red-team exercise

---

## Principle 2: One-way data diodes on safety-critical paths

**Charter reference:** §4.5.3 — "One-way data diodes on safety-critical paths (formation cycling, electrolyte injection)."

### Interface

```
DATA_DIODE.allow_direction(direction: 'in' | 'out', data: bytes) -> Decision
```

### Specification

- One-way data diodes are PHYSICAL hardware devices, not software
- Installed on safety-critical paths: formation cycling, electrolyte injection
- Direction: only OUT (data can flow OUT for monitoring; no commands can flow IN)
- Physical enforcement (e.g., fibre-optic one-way transmitter)
- Cannot be configured to allow bidirectional traffic

### Properties

- **Hardware-enforced:** Cannot be bypassed by software configuration
- **No firmware update path:** The diode is a separate physical device
- **Failure mode:** If the diode fails, the safe state is "no traffic" (not "all traffic")

### Reference implementation

- Not implemented in software; this is a physical device procurement
- Track A (Architecture) procures and installs
- Tested in Weeks 8-10; verified in the G4 red-team exercise

---

## Principle 3: Cryptographic recipe signing

**Charter reference:** §4.5.3 — "Cryptographic recipe signing. PLCs reject unsigned or modified recipes."

### Interface

```
RECIPE_SIGNING_SERVICE.sign_recipe(recipe: ProcessRecipe) -> SignedRecipe
RECIPE_SIGNING_SERVICE.verify_recipe(signed: SignedRecipe) -> bool
PLC_RECIPE_VERIFIER.apply_recipe(signed: SignedRecipe) -> bool
```

### Specification

- Recipe signing algorithm: **Ed25519** (or equivalent, agreed at G1)
- Signing key storage: **Hardware Security Module (HSM)** held by Track A
- Signing key never leaves the HSM
- PLC firmware holds the public key (or fetches from a trusted source)
- PLC rejects any recipe with:
  - Missing signature
  - Invalid signature
  - Unknown signing key (key not in the allowed list)
  - Recipe version older than the currently active version
- Every signing and verification operation is logged to the audit trail

### Properties

- **Tamper-resistant:** Even an attacker with full SCADA/MES compromise cannot forge a valid signature
- **Forward-compatible:** Key rotation is supported (PLC firmware can be updated with a new public key)
- **Versioned:** Recipes have explicit version numbers to prevent rollback attacks

### Reference implementation

- `01-reference-implementations/poka-yoke/cryptographic_recipe_signer.py`
- Includes `RecipeSigningService` (HSM wrapper) and `PLCRecipeVerifier` (PLC-side verification)

### Deployment

- Track A (Architecture) owns the HSM
- Track A maintains the public key distribution to all PLCs
- Every recipe change requires re-signing
- Audit trail captures every signing and verification

---

## Principle 4: Vendor remote access through authenticated broker

**Charter reference:** §4.5.3 — "Vendor remote access through authenticated broker with cryptographic handshake. No direct VPN."

### Interface

```
VENDOR_BROKER.authenticate(vendor_id, credentials, mfa_token) -> Session
VENDOR_BROKER.authorize(session, requested_resource) -> bool
VENDOR_BROKER.record_session(session, actions) -> AuditEntry
VENDOR_BROKER.terminate(session) -> None
```

### Specification

- All vendor remote access flows through a single authenticated broker
- Vendors NEVER have direct VPN access to the OT network
- Authentication: vendor credentials + MFA (TOTP, FIDO2, or equivalent)
- Session: time-bounded (max 4 hours), session-recorded, all actions logged
- Authorization: per-vendor ACL (vendor can only access systems they're contracted to support)
- Cryptographic handshake: every session starts with mutual authentication
- Just-in-time access: vendor sessions are scheduled, not standing

### Properties

- **Audit-complete:** Every action is recorded; vendor behaviour is reviewable
- **Bounded:** Sessions are time-limited, vendor access is just-in-time
- **Revocable:** CISO can terminate any session immediately
- **Segmented:** Vendor can only reach their contracted systems, not the whole OT network

### Reference implementation

- Not implemented in this folder (procurement of vendor broker product, e.g., CyberArk, BeyondTrust, Teleport)
- Track A (Architecture) procures, configures, and maintains

---

## Principle 5: Parameter drift interlocks with auto-isolation

**Charter reference:** §4.5.3 — "Real-time comparison of process parameters against the signed baseline recipe. Drift beyond a defined threshold triggers automatic line isolation."

### Interface

```
PARAMETER_DRIFT_INTERLOCK.check_parameter(observed: float) -> InterlockEvent
```

### Specification

- Real-time comparison of observed process parameters against signed baseline recipes
- Drift threshold per parameter (typically 1-5% depending on process step)
- Auto-isolation when drift exceeds threshold:
  - Line segment is isolated (emergency-stop signal to PLC)
  - Forensic state is snapshotted (to immutable backup)
  - CISO is notified (within 15 min for hard stop, within 1 min for safety-critical)
- **Fail-closed:** If the interlock encounters any error (signature verification, monitoring, isolation), the line is isolated. Never allowed to continue with unknown state.
- Audit trail: every check, every drift event, every isolation is logged

### Properties

- **Real-time:** Checks happen continuously (sub-second latency)
- **Signed baselines:** Baselines are cryptographically signed (Poka-Yoke #3)
- **Auto-isolation:** No human in the loop for the isolation decision
- **Fail-closed:** Safer to isolate than to allow drift to continue
- **Auditable:** Every check is logged; every action is reviewable

### Reference implementation

- `01-reference-implementations/poka-yoke/parameter_drift_interlock.py`
- `SignedBaseline` dataclass
- `ParameterDriftInterlock` class with `check_parameter()` and `get_state()` methods
- Includes the FAULT-CLOSED behaviour as a primary design property

### Deployment

- Track A (Architecture) owns the PLC firmware integration
- Track C (Automation) owns the Python orchestrator
- Tested in Weeks 8-10; validated in the G4 red-team exercise

---

## Cross-cutting properties

All 5 Poka-Yoke principles share these properties:

1. **Structural, not procedural:** The controls are enforced by code, firmware, or hardware — not by human procedures
2. **Fail-closed:** If anything fails, the safe state is reached
3. **Auditable:** Every enforcement action is logged
4. **Testable:** Each principle has a clear test (e.g., parameter_drift_interlock has unit tests with 100% pass on safety-critical)
5. **Six Sigma-aligned:** Cpk ≥ 2.0 on every control mechanism

## How the 5 principles map to FMEA modes

| Poka-Yoke | FMEA modes addressed | Effect |
|---|---|---|
| #1 Hard-coded network isolation | #7 (electrolyte dosing), #8 (formation charging), #10 (electrolyte) | Blocks inbound attacker traffic |
| #2 One-way data diodes | #8 (formation charging), #10 (electrolyte) | Physically prevents command injection on safety paths |
| #3 Cryptographic recipe signing | #1, #2, #4, #5, #6, #7 (all SC modes) | Prevents parameter tampering at source |
| #4 Vendor remote access broker | #11 (batch tracking), #12 (auth bypass) | Constrains vendor compromise blast radius |
| #5 Parameter drift interlocks | #1, #2, #3, #4, #5, #6, #7 (all SC modes) | Detects tampering in real-time; auto-isolates line |

**5 of the 7 silent corruption modes (FMEA #1-7) are addressed by 3+ Poka-Yoke principles each.** This is the structural defence in depth.
