---
title: Cyber Resilience Charter — Six Sigma Aligned
engagement: Global EV Cell Manufacturing — Phase 1 (Define)
methodology: Lean Six Sigma MBB / DMAIC
status: Ready for CISO G1 review
capability_target: Z ≥ 6.0 (theoretical Six Sigma)
engagement_window: 12 weeks, 5 tollgates
team: 19 Green Belts × 10% = 1.9 FTE + 1.0 FTE MBB
tags:
  - consulting
  - lean-six-sigma
  - mbb
  - cyber-resilience
  - ev-cell-manufacturing
  - dmaic
  - project-charter
  - ciso-engagement
---

# Cyber Resilience Charter — Six Sigma Aligned

**Engagement:** Zero production downtime from cyber attacks and viruses, in the context of the same global EV cell manufacturing consultation that produced the Operational Stability Infrastructure (OSI) whitepaper.

**Public deliverables (anonymised, Six Sigma aligned):**
- Full charter (8 sections + 2 appendices, ~40-50 pages): https://87x1siaib1okk.space.minimax.io
- Standalone CISO Executive Dashboard (interactive 8-tile mockup): https://6z9fkk0oehsun.space.minimax.io
- Standalone CISO dashboard (additional deployment): https://vmn4dy5p05641.space.minimax.io

**Local source files:**
- `Cyber-Resilience-Project-Charter.docx` — editable Word document for CISO meeting
- `Cyber-Resilience-Project-Charter.pdf` — read-only PDF for distribution
- `cyber-resilience-charter.html` — HTML bundle with embedded dashboard
- `ciso-dashboard-mockup.html` — standalone interactive dashboard

---

## 1. Problem framing

"No production downtime due to cyber attacks and viruses" — reframed as a **manufacturing process defect**, not an IT security issue. The engagement applies DMAIC discipline to the IT/OT convergence stack with the cell manufacturing value stream (mixing → coating → assembly → electrolyte injection → formation & aging → grading) as the unit of analysis.

Why LSS MBB is the right methodology: cyber-induced downtime is a defect class with measurable rates, capability indices, and statistical control. IT security alone (perimeter defence, threat hunting) cannot see the binding failure class — **silent corruption** — which is the largest exposure.

---

## 2. Five exposure classes (P × E × M model)

Reuses the OSI whitepaper's P × E × M model: Exposure = P × E; Protected Value = Exposure × M.

| Class | Annual band / dept | Anchor |
|---|---|---|
| **E_downtime** | $4M–$20M | 5–21 day major event × $30M–$100M direct cost × 1/5–7 yr frequency |
| **E_silent_corruption** (NEW — broken out) | $5M–$50M | 1 in 2–5 yr frequency, $25M–$200M+ per event (recall + warranty + OEM contractual) |
| **E_ip** | $10M–$100M | Battery chemistry IP at $100M–$1B+ per platform × 1/3–10 yr (state-aligned APT target; uninsurable) |
| **E_regulatory** | $1M–$10M | NIS2 (€10M / 2% turnover), GDPR (€20M / 4% turnover), OEM cyber attestation |
| **E_safety** (unbounded tail) | $5M–$unbounded | EU PLD 2024/2853 strict liability, US class action $50M–$1B+, low-prob/high-severity |

**E_cyber total:** $20M–$180M+ / year / department (excluding unbounded safety tail), **3–11× the OSI entropy band of $6M–$16M**.

5-site enterprise protected value at M=25%: **$25M–$225M+ / year**.

---

## 3. Cyber-FMEA — top 12 failure modes (RPN-ranked, S recalibrated to 10 for all SC modes)

7 of 12 modes are **silent corruption** (SC) — parameter tampering, no halt, cells pass inspection, fail in field. All SC modes at S=10. The top 5 RPN modes (≥ 450) are all silent corruption.

| # | Step | Failure Mode | S × O × D | RPN |
|---|---|---|---|---|
| 1 | Formation (SC) | Aging cycle manipulation → recall | 10 × 6 × 9 | 540 |
| 2 | Coating (SC) | Coating thickness tampering → fire risk | 10 × 7 × 7 | 490 |
| 3 | Slurry (SC) | Sensor data spoofing → defective slurry | 10 × 6 × 8 | 480 |
| 4 | Grading (SC) | Capacity test data tampering → recall | 10 × 5 × 9 | 450 |
| 5 | Coating (SC) | Vision system data spoofing → field failure | 10 × 5 × 9 | 450 |
| 6 | Assembly (SC) | Stacking parameter tampering → field failure | 10 × 5 × 8 | 400 |
| 7 | Grading (SC) | IR test data manipulation → thermal event | 10 × 4 × 9 | 360 |
| 8 | Formation | Charging profile tampering → thermal runaway | 10 × 5 × 7 | 350 |
| 9 | Slurry | Ransomware locks Industrial PC | 8 × 7 × 6 | 336 |
| 10 | Electrolyte Inj | Dosing volume tampering → safety hazard | 10 × 4 × 8 | 320 |
| 11 | Slurry | Batch tracking malware → traceability | 7 × 5 × 7 | 245 |
| 12 | Assembly | Authentication bypass → recipe change | 9 × 3 × 7 | 189 |

**Silent corruption is the binding risk class.** This validates the structural decision to break it out as its own exposure line (#2) and the AI-augmented Layer 3 design (#5).

---

## 4. Six Sigma targets (theoretical, Z ≥ 6.0)

| Sub-process | Cpk | Operational |
|---|---|---|
| Detection — known signatures | ≥ 2.0, Z ≥ 6.0 | MTTD ≤ 2 min |
| Detection — novel OT anomalies | ≥ 2.0, Z ≥ 6.0 | MTTD ≤ 10 min (AI-augmented) |
| Response — hard stop (ransomware/wiper) | ≥ 2.0, Z ≥ 6.0 | MTTR ≤ 1 hour |
| Response — OT compromise (silent corruption) | ≥ 2.0, Z ≥ 6.0 | MTTR ≤ 8 hours |
| Prevention (patch compliance) | ≥ 2.0, Z ≥ 6.0 | ≥ 99% in maintenance windows |
| Risk reduction (FMEA) | — | RPN reduction ≥ 80% across top 10 modes |

**Engagement-level target:** Z ≥ 6.0 (0.002 DPMO short-term / 3.4 DPMO with 1.5σ long-term drift shift). Capability indices (Cpk, Z) are the binding MBB metrics; time values are operational translations validated in the Measure phase (Tollgate G2).

---

## 5. Four-layer OSI → cyber translation

The OSI whitepaper's 4-layer framework maps to cyber domain content:

- **Layer 1 — Entropy Containment → Cyber Hygiene:** IT/OT asset inventory, network segmentation, patch discipline, vendor remote-access hardening, backup integrity, least privilege, **Digital 5C** (Sort/Straighten/Shine/Standardise/Sustain)
- **Layer 2 — Visual Flow → Cyber Visibility:** Network traffic baselining, asset communication maps, threat intel integration, SOC visibility into OT, anomaly dashboards
- **Layer 3 — Abnormality Detection → AI-Augmented Layer 3:** Four autonomous agents operating within data-access protocol — SOC Triage Agent, OT Anomaly Detection Agent, IR Automation Agent, Threat Intel Correlation Agent. CISO retains kill-switch authority on every agent.
- **Layer 4 — Governance → Cyber Governance:** Layered cyber audits, cross-site threat-intel sharing, NIST CSF tier scoring, quarterly red-team, board-level cyber reporting

**Cyber Poka-Yoke (5 structural principles, Layer 1/2):**
1. Hard-coded network isolation at PLC firmware level (not just firewall)
2. One-way data diodes on safety-critical paths
3. Cryptographic recipe signing (formation, coating, dosing, aging)
4. Vendor remote access through authenticated broker (no direct VPN)
5. Parameter drift interlocks with auto-isolation

**SMED for Disaster Recovery (Layer 1/2):** internal (during attack) → external (pre-staged) conversion. Immutable offline hot-swap backups, pre-built recovery rigs, pre-authorised runbooks, clean-state validation before vendor reconnection.

---

## 6. Data-Access Governance (the Data-Blind Protocol)

The CISO's largest single decision. The trust boundary for the entire engagement:

- **ALLOWED** (GB read-only): time deltas, compliance %, defect rates, traffic volumes, capability indices
- **RESTRICTED** (CISO team only): IP addresses, hostnames, MAC addresses, raw network logs, vendor credentials, proprietary configs
- **PROHIBITED:** anything identifying a specific asset, person, vendor, or proprietary system

**Data flow:** Raw data → CISO-controlled anonymisation pipeline → Anonymised data lake → GB query interface. GBs never access raw data. Anonymisation pipeline is CISO-controlled, not GB-controlled.

**Breach protocol:** Immediate access revocation (1h) → forensic review (24h) → engagement pause → re-permissioning requires CISO sign-off + Track Lead attestation + MBB approval. Confirmed breach → Tier 4 escalation, possible engagement termination at CISO discretion.

---

## 7. 12-week execution (Gantt, 3 tracks, 5 tollgates)

| Phase | Weeks | Tollgate | Track outputs converge to |
|---|---|---|---|
| Define | 1–3 | G1 | Charter, Digital VSM, data-blind SIPOC, code standards |
| Measure | 4–5 | G2 | Z-score baseline, anonymised data lake, MTTD/MTTR distributions |
| Analyse | 6–7 | G3 | Prioritised FMEA, 5-Why on top 5, control-point design |
| Improve | 8–10 | G4 | Segmentation, Poka-Yoke, SMED rig, AI-augmented Layer 3, Digital 5C |
| Control | 11–12 | G5 | SPC charts, control plan, Standard Work, joint sign-off |

**Critical path is Track B driven** (data lake → baseline → RPN → SPC → G5). A 1-week data lake slip cascades through the entire engagement.

**3 tracks:** Track A (6 GBs, Architecture), Track B (7 GBs, Data & Metrics), Track C (6 GBs, Automation). All at 10% weekly capacity allocation (1.9 FTE effective team).

---

## 8. Continuation (Standard Work, Kaizen, Maturity, Replication)

After G5, the engagement becomes **operational infrastructure** rather than a one-time project. Three continuation disciplines:

1. **Standard Work** — weekly/monthly/quarterly/annual routines at 10% GB capacity. 100% compliance target. Non-compliance → Tier 2 → MBB → persistent → Tier 3 → CISO.
2. **13 Cyber-Kaizen Triggers** — 10 routine (SPC UCL, MTTR breach, new asset, regulatory change, peer event, personnel, audit finding, AI drift, process change, tooling) + 3 structural (supply chain, M&A, IP licensing). All → A3 within 5 BD; structural → Tier 3 CISO.
3. **Maturity Scoring** — 5 levels (Initial → Managed → Defined → Quantitatively Managed → Optimising). Target Level 4 by G5, Level 5 sustained long-term. Regression triggers escalation.

**Cross-site replication:** Site 2 (M4-6), Site 3 (M7-9), Site 4 (M10-12), Site 5 (M13-15), Enterprise benchmark (M18+). Each site runs 12-week cycle with site MBB mentored by engagement MBB.

---

## 9. CISO governance cycle

- **Executive Dashboard** (8 tiles, real-time Z-score, COPQ protected, MTTD/MTTR, RPN, Kaizen, maturity, regulatory)
- **Bi-weekly briefings** (30 min, CISO + MBB)
- **Bi-annual audits** (half-day, CISO + MBB + Operations + IT Security + Legal)
- **Annual strategic review** (full-day, CISO + MBB + executive committee)

Dashboard target line: **Z = 6.0** (Six Sigma). RED threshold: Z < 5.5. 3-tier color coding (GREEN/AMBER/RED).

---

## 10. Risk register (8 risks, sharpest)

| # | Risk | P × I | Score |
|---|---|---|---|
| 1 | Data lake deployment slips past W4 (Track B critical path) | 3 × 5 | 15 |
| 2 | GB capacity conflict at peak load (W6–W10) | 4 × 4 | **16** |
| 3 | Vendor remote-access resistance | 3 × 4 | 12 |
| 4 | AI agent build/buy decision blocked | 3 × 4 | 12 |
| 5 | Real cyber event during engagement | 2 × 5 | 10 |
| 6 | Engagement scope creep | 3 × 3 | 9 |
| 7 | CISO sign-off delays at tollgates | 2 × 4 | 8 |
| 8 | Regulatory/contractual change mid-engagement | 2 × 4 | 8 |

**7 residual risks accepted at G1:** silent corruption recall window, IP exfiltration (detect not prevent), unbounded safety tail (Severity=10), vendor endpoint compromise, regulatory change, cross-site Level 5 timing, GB over-allocation.

---

## 11. Why this engagement is different from OSI entropy

| Dimension | OSI (Entropy) | Cyber (This Engagement) |
|---|---|---|
| Erosion band | 3–8% of P | 10–90%+ of P |
| Per-dept annual exposure | $6M–$16M | $20M–$180M+ |
| Insurability | Partial | Low (IP and safety largely uninsurable) |
| AI augmentation | Low (process control is human) | **High (Layer 3 home for autonomous agents)** |
| Regulatory dimension | Quality/environmental | NIS2, IEC 62443, OEM attestation, GDPR, PLD |

Same MBB methodology. Materially larger cost-of-no-action.

---

## 12. Cross-references

- **Same client engagement** produced the OSI whitepaper and the LSS MBB 5S
- **MBB methodology** foundations: `C:\Users\olivi\Business\06 — Education & Knowledge\MBB_Methodology_Core`
- **AWS ML AI Fundamentals** (for AI agent design patterns in Layer 3)
- **GitHub repo (this engagement):** the public repository for the engagement, with the charter deliverables and Phase 4 implementation code

---

## 13. Engagement context

- **Client:** Global EV cell manufacturing department ($1.2bn operation, $200M annual production value per department)
- **Confidentiality constraint:** Internal network configurations, IP addresses, and proprietary systems protected by the data-access protocol (#6)
- **Cross-site scope:** 5 production sites (Site 1 = origin, Sites 2-5 = replication over 15 months)
- **Stakeholders:** CISO (Executive Sponsor), Operations Director, OT Engineering, IT Security, Safety Officer, Legal/Compliance, OEM customers
