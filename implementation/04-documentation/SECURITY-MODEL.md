# Security Model — Cyber Resilience Implementation

## Trust zones

The implementation enforces a strict 4-zone trust model. Every component knows which zone it belongs to and what data it can access.

```
┌─────────────────────────────────────────────────────────────────────────┐
│ ZONE 1: RAW DATA  (highest trust required)                             │
│                                                                          │
│   Access: CISO team only                                                │
│   Data: IP addresses, hostnames, MAC addresses, raw logs, credentials    │
│   Authentication: HSM-backed multi-factor, audited access                 │
│   Audit: every access logged to immutable store                         │
│   Rotation: quarterly access review                                    │
└─────────────────────────────────────────────────────────────────────────┘
                                 ▲ only CISO team
                                 │
┌─────────────────────────────────────────────────────────────────────────┐
│ ZONE 2: ANONYMISATION PIPELINE  (high trust)                            │
│                                                                          │
│   Access: CISO team only                                                │
│   Operation: transforms raw data → ALLOWED outputs                      │
│   Integrity: cryptographically verified pipeline; quarterly 3rd party   │
│   Audit: every transformation logged                                    │
└─────────────────────────────────────────────────────────────────────────┘
                                 ▲ only ALLOWED outputs
                                 │
┌─────────────────────────────────────────────────────────────────────────┐
│ ZONE 3: ANONYMISED DATA LAKE  (medium trust)                            │
│                                                                          │
│   Access: 19 GBs (read-only via interface) + 4 AI agents (read-only)    │
│   Authentication: per-user credentials, MFA required                    │
│   Authorisation: per-role (Track A / B / C)                              │
│   Audit: every query logged; quarterly access review                     │
│   Bounded: max_rows=10000, timeout_sec=30                               │
└─────────────────────────────────────────────────────────────────────────┘
                                 ▼ only action outputs
                                 │ (no data crosses this direction)
┌─────────────────────────────────────────────────────────────────────────┐
│ ZONE 4: CONTROL PLANE  (action output)                                  │
│                                                                          │
│   Output: Poka-Yoke enforcement, SMED recovery, IR automation, dashboard│
│   No raw data; only structured action commands                          │
│   Authentication: per-component credentials, rotated quarterly          │
│   Audit: every action logged to immutable store                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Authentication and authorisation

### CISO team (Zones 1, 2)

- **Authentication:** Hardware Security Module (HSM)-backed multi-factor authentication
- **Authorisation:** Role-based (CISO, CISO team, no individual override of CISO)
- **Sessions:** 4-hour maximum, re-authentication required
- **Audit:** Every action logged with timestamp, user, action, justification

### Green Belts (Zone 3)

- **Authentication:** Per-user credentials with multi-factor authentication
- **Authorisation:** Per-track role (Track A / B / C); GBs can only access their track's relevant data
- **Sessions:** 8-hour maximum
- **Audit:** Every query logged with timestamp, user, role, query_hash, params_hash, row_count

### AI agents (Zone 3)

- **Authentication:** Service-to-service credentials, rotated monthly
- **Authorisation:** Read-only; agents cannot modify the data lake
- **Session:** Continuous (long-running)
- **Audit:** Every query logged; every action logged with timestamp, agent_id, action_type, details

### Kill switch (CISO authority)

- **Configuration:** JSON file at `/etc/cyber-resilience/kill-switch/{agent_id}.json`
- **Authority:** CISO or CISO delegate
- **Action:** Setting `{"enabled": false}` immediately disables the agent
- **Audit:** Kill and revive events logged with reason and approver

## Cryptographic controls

### Recipe signing (Poka-Yoke #3)

- **Algorithm:** Ed25519 (or equivalent)
- **Key storage:** Hardware Security Module (HSM); signing key NEVER leaves HSM
- **Key rotation:** Annually or on suspected compromise
- **Key access:** CISO team only, multi-person approval for signing operations
- **Public key distribution:** Track A distributes public key to all PLCs; PLC firmware verifies before applying any recipe
- **Audit:** Every signing operation logged to immutable store

### Parameter drift interlock (Poka-Yoke #5)

- **Baseline storage:** Anonymised data lake, signed by Track A's signing service
- **Verification:** Every parameter check verifies baseline signature before comparison
- **Failure mode:** If signature verification fails, baseline is rejected; line is isolated (fail-closed)
- **Audit:** Every check logged; every isolation logged with reason

### Audit log integrity

- **Format:** JSONL (one JSON object per line)
- **Hash chaining:** Each entry includes hash of previous entry (tamper-evident)
- **Storage:** Immutable store (write-once-read-many or similar)
- **Review cadence:** Monthly by CISO team, quarterly by 3rd party
- **Retention:** 7 years minimum (regulatory requirement)

## Data classification enforcement (#3.5)

The Data-Blind Protocol is enforced at three levels:

### Level 1: Schema-level (database)

- Only ALLOWED tables/columns exist in the anonymised data lake
- Restricted and Prohibited data never enters the anonymised data lake
- Anonymisation pipeline is the only path from Zone 1 to Zone 2

### Level 2: Query-level (interface)

- Every query is validated against ALLOWED/RESTRICTED patterns
- Restricted patterns (IP, hostname, raw logs, etc.) raise `DataAccessError` immediately
- Write operations (INSERT/UPDATE/DELETE/DROP/ALTER/TRUNCATE/CREATE) are rejected
- Bounded results (max_rows, timeout_sec) prevent resource exhaustion

### Level 3: Application-level (agents and GBs)

- Agents are designed to only query ALLOWED tables/columns
- GBs are trained on the Data-Blind Protocol before accessing the data lake
- Any attempt to access restricted data is logged and triggers Tier 2 escalation
- CISO team audits the query patterns quarterly

## Network segmentation

Following the Purdue Model (IEC 62443):

- **Levels 0-1:** Field devices and PLCs (air-gapped from corporate IT, with one-way data diodes on safety-critical paths)
- **Levels 2-3:** SCADA and HMI (in OT DMZ, segmented from corporate IT)
- **Level 3.5:** DMZ (data diodes allow data to flow out for monitoring, no command flow in)
- **Level 4-5:** Corporate IT and enterprise systems (segmented from OT)
- **Vendor remote access:** Through authenticated broker only (no direct VPN)

## Poka-Yoke enforcement security

The 5 Poka-Yoke principles are enforced as security controls:

1. **Hard-coded network isolation at PLC firmware level** — bypassed only by physical access to the PLC; firmware is signed and verified
2. **One-way data diodes on safety-critical paths** — physical hardware; cannot be configured to allow inbound traffic
3. **Cryptographic recipe signing** — signing key in HSM; PLC verifies before applying
4. **Vendor remote access through authenticated broker** — broker enforces MFA, time-bounded sessions, session recording
5. **Parameter drift interlocks with auto-isolation** — fail-closed; line stays isolated on any error

## AI agent security

### Trust boundaries

- AI agents have NO direct access to raw data; all access via the anonymised data lake
- AI agents have NO write access to the data lake
- AI agents can only execute pre-authorised playbooks (CISO standing approval for Severity ≥ 8)
- AI agents cannot modify the Poka-Yoke enforcement configuration

### Action validation

- Every AI agent action is validated before execution:
  - Classification must reach a confidence threshold
  - Routing must match the action's required authorisation
  - Pre-authorisation must be valid (CISO standing approval for playbooks)
- Failed validation → escalate to human (Tier 1/2/3 depending on severity)

### Kill switch

- CISO can disable any agent at any time by flipping a config flag
- Kill switch is checked at the start of every action
- Kill events are logged with reason and approver
- Revival requires explicit CISO action with logged reason

## SMED recovery security

- **Pre-staged assets** (backups, restore rigs, golden images) are stored in air-gapped locations
- **Pre-validated golden images** are cryptographically signed by Track A
- **Pre-authorised runbooks** are CISO-approved at G1
- **Per-incident CISO approval** required for runbooks without standing approval
- **Clean-state validation** is mandatory before line resumes production
- **Vendor reconnection** is allowed only after clean-state validation

## Threat model

The implementation defends against the following threat actors:

### Tier 1 threats (low sophistication)

- **Insider threat (low privilege):** Mitigated by data-access protocol, audit log, least-privilege access
- **Opportunistic attacker (commodity malware):** Mitigated by Poka-Yoke #4 (vendor remote access), patch compliance, network segmentation

### Tier 2 threats (moderate sophistication)

- **Targeted attack on OT/ICS:** Mitigated by Layer 3 AI agents, parameter drift detection, Poka-Yoke enforcement
- **Ransomware targeting manufacturing:** Mitigated by immutable offline backups, SMED recovery rig, Poka-Yoke enforcement
- **Supply chain compromise:** Mitigated by cryptographic recipe signing, vendor remote access broker, FMEA refresh on tool change

### Tier 3 threats (high sophistication)

- **State-aligned APT targeting chemistry IP:** Mitigated by 7 silent corruption detection modes, AI-augmented Layer 3, MTTD ≤ 10 min, MTTR ≤ 1 hour
- **Compromise of CISO team:** Mitigated by 4-eye principle on HSM access, quarterly 3rd party audit, immutable audit log
- **Compromise of MES/PLCs:** Mitigated by Poka-Yoke enforcement (rejects unsigned recipes), parameter drift detection, SMED recovery

### Tier 4 threats (existential)

- **Safety event triggered by cyber compromise:** Mitigated by Severity = 10 in FMEA, one-way data diodes on safety-critical paths, EU PLD governance, Tier 4 escalation
- **IP exfiltration (uninsurable):** Mitigated by E_ip exposure modelling, FMEA top-12, AI-augmented detection, M&A / IP licensing Kaizen triggers
- **Mass-casualty safety event:** Beyond the scope of the engagement; would trigger emergency response and executive-level decisions

## What this means for the engagement

The security model is **structural, not procedural**. The Data-Blind Protocol is enforced at the schema, query, and application levels. The Poka-Yoke principles are enforced at the firmware, hardware, and software levels. The AI agents are constrained by design (kill switch, bounded access, idempotent operations). The SMED recovery is pre-staged and pre-authorised.

This is what makes Six Sigma capability (Z ≥ 6.0) achievable in OT cyber: not by adding more procedures, but by making certain failure modes structurally impossible.
