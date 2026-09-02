# Cyber Resilience Project Charter

> **Zero production downtime from cyber attacks and viruses** — in global EV cell manufacturing, treated as a manufacturing process defect, governed by Lean Six Sigma discipline at theoretical Six Sigma capability (Z ≥ 6.0).

[![Status](https://img.shields.io/badge/Status-Phase%201%20Define%20Final-success)]()
[![Capability Target](https://img.shields.io/badge/Capability%20Target-Z%20%E2%89%A5%206.0-blue)]()
[![Engagement](https://img.shields.io/badge/Engagement-12%20Weeks%20%C3%97%2019%20GBs-orange)]()

## What is this?

A two-phase Lean Six Sigma MBB engagement for an EV cell manufacturing client (same engagement that produced the Operational Stability Infrastructure whitepaper).

**Phase 1 (Define) — this repository's primary content:** the strategic charter, business case, FMEA, governance framework, and Six Sigma-aligned target architecture.

**Phase 4 (Improve) — `implementation/`:** the reference code the 19 Green Belts deploy in Weeks 8–10 to achieve the targets.

## Project contents

```
cyber-resilience-charter/
├── README.md                                    # you are here
├── LICENSE                                      # MIT
├── CHANGELOG.md                                 # release notes
├── .gitignore                                   # standard Python .gitignore
├── docs/
│   ├── 01-charter/                              # Phase 1 (Define) — client deliverables
│   │   ├── charter.docx                          # editable Word (primary)
│   │   ├── charter.pdf                           # read-only PDF
│   │   ├── charter.html                          # self-contained HTML bundle
│   │   ├── dashboard.html                        # standalone interactive dashboard
│   │   ├── client-package.zip                    # email-ready ZIP (4 files + README)
│   │   └── README.md                             # package index
│   ├── 02-public-urls.md                         # the 3 live public URLs
│   └── 03-obsidian-note.md                       # Obsidian project note (in your vault)
├── implementation/                              # Phase 4 (Improve) — code
│   ├── README.md                                 # overview, deploy guide, constraints
│   ├── 00-specifications/                        # contracts, interfaces, schemas
│   │   ├── ai-agents/AGENT_SPECS.md              # 4 AI agents
│   │   ├── poka-yoke/POKA_YOKE_SPECS.md          # 5 Poka-Yoke principles
│   │   ├── smed/SMED_SPECS.md                    # recovery rig
│   │   ├── data-lake/DATA_LAKE_SPECS.md          # anonymised data lake
│   │   ├── dashboard/DASHBOARD_SPECS.md          # 8-tile dashboard
│   │   └── fmea/FMEA_SPECS.md                    # FMEA control plan
│   ├── 01-reference-implementations/             # production-quality reference code
│   │   ├── ai-agents/                            # 4 agents + base class
│   │   ├── poka-yoke/                            # 2 enforcers
│   │   ├── smed/                                 # recovery rig
│   │   └── data-lake/                            # query interface
│   ├── 02-tests/                                 # pytest test suites
│   ├── 03-deployment/                            # deploy script + requirements
│   └── 04-documentation/                         # ARCHITECTURE, DATA-FLOW, OPERATIONS, SECURITY-MODEL
```

## Headline numbers

| Metric | Value |
|---|---|
| Capability target | **Z ≥ 6.0** (theoretical Six Sigma, 0.002 DPMO short-term / 3.4 DPMO with 1.5σ shift) |
| Cpk target | **≥ 2.0** across every sub-process |
| Exposure band | **$20M–$180M+ / year / department** (5 exposure classes) |
| 5-site enterprise protected value | **$25M–$225M+ / year** (conservative capture M=25%) |
| Cyber-FMEA | 12 top modes, **7 of 12 are silent corruption (S=10, top 5 RPN ≥ 450)** |
| 5 Cyber Poka-Yoke principles | Hard-coded network isolation, one-way data diodes, cryptographic recipe signing, vendor remote-access broker, parameter drift interlocks |
| 4 AI agents | SOC Triage, OT Anomaly Detection, IR Automation, Threat Intel Correlation |
| Team | 19 Green Belts × 10% weekly capacity = **1.9 FTE** + 1.0 FTE MBB |
| Duration | 12 weeks, 5 tollgates (G1 Define → G5 Control) |
| CISO | Executive Sponsor & Process Owner — sole signatory on every tollgate |

## Where to start

- **If you are the CISO or an executive reviewer:** open [`docs/01-charter/charter.pdf`](docs/01-charter/charter.pdf) or the [HTML bundle](docs/01-charter/charter.html) in a browser. The CISO Elevator Pitch is in #A.1 of the charter.
- **If you are a Green Belt on the 19-engineer team:** start at [`implementation/README.md`](implementation/README.md) — it explains which track you're on and which files to read.
- **If you are a technical reviewer:** start at [`implementation/04-documentation/ARCHITECTURE.md`](implementation/04-documentation/ARCHITECTURE.md) for the system view, then drill into the reference implementations.
- **If you are an external consultant running a similar engagement:** this repo is a reference architecture. Read the methodology (DMAIC + FMEA + LSS MBB) and adapt.

## Live public URLs

Three public deployments are live (anonymised, Six Sigma aligned, G5 illustrative state):

- **Full charter bundle** (8 sections + 2 appendices + embedded dashboard): https://87x1siaib1okk.space.minimax.io
- **Standalone CISO dashboard** (original): https://6z9fkk0oehsun.space.minimax.io
- **Standalone CISO dashboard** (additional deployment): https://vmn4dy5p05641.space.minimax.io

See [`docs/02-public-urls.md`](docs/02-public-urls.md) for the deployment pattern and node IDs.

## Why Six Sigma (not 4.5σ, not 5σ)?

The engagement targets **Z ≥ 6.0** (theoretical Six Sigma):

- **Methodology:** full DMAIC, FMEA, SPC, MBB discipline — Six Sigma throughout
- **Target:** Z ≥ 6.0 short-term (0.002 DPMO) / 3.4 DPMO with 1.5σ long-term shift
- **Cpk:** ≥ 2.0 across every sub-process (Detection known, Detection novel, Response hard stop, Response OT compromise, Prevention)
- **Operational translations:** MTTD ≤ 2 min (known sigs) / ≤ 10 min (novel); MTTR ≤ 1 hour (hard stop) / ≤ 8 hours (OT compromise); patch compliance ≥ 99%; FMEA RPN reduction ≥ 80% across top 10 modes

The structural controls (Poka-Yoke, SMED, AI-augmented Layer 3, cryptographic signing) are sized for Six Sigma. Anything less is a different programme.

## Five exposure classes

The charter decomposes cyber exposure into five classes (#2.2):

1. **E_downtime** — hard-stop events (ransomware, wiper, MES compromise): $4M–$20M / yr / dept
2. **E_silent_corruption** (broken out) — parameter tampering, no halt, in-line inspection passes, field failure: $5M–$50M / yr / dept
3. **E_ip** — battery chemistry IP exfiltration ($100M–$1B+ per platform): $10M–$100M / yr / dept
4. **E_regulatory** — NIS2, GDPR, OEM cyber attestation: $1M–$10M / yr / dept
5. **E_safety** — existential tail (EU PLD 2024/2853 strict liability, US class action $50M–$1B+): $5M–$unbounded / yr

**Total E_cyber:** $20M–$180M+ / year / department — 3–11× the OSI entropy framework's $6M–$16M band.

## Methodology map

- **#1 Executive Summary** — engagement at a glance, strategic alignment, target outcomes (Six Sigma)
- **#2 Business Case** — P × E × M model, 5 exposure classes, COPQ, multi-site multiplier, OSI comparison
- **#3 CISO Strategic Alignment** — role architecture, RACI matrix, tollgate sign-off authority, escalation, **Data-Access Governance (the Data-Blind Protocol)**
- **#4 DMAIC Methodology** — Define, Measure, Analyse, Improve, Control; **Cyber-FMEA top 12** (S recalibrated to 10 for SC modes); **Digital 5C**, **Cyber Poka-Yoke** (5 principles), **SMED for Disaster Recovery**, **AI-Augmented Layer 3** (4 agents)
- **#5 Implementation Roadmap** — 12-week Gantt with 3 tracks, cross-track dependencies, **Track B critical path**, tollgate calendar, GB utilisation, risk-based decision points
- **#6 Continuation & Standard Work** — Standard Work (weekly/monthly/quarterly/annual), **13 Cyber-Kaizen triggers**, Maturity Scoring, Cross-Site Replication
- **#7 CISO Governance Cycle** — **8-tile Executive Dashboard**, bi-weekly briefings, bi-annual audits, annual strategic review
- **#8 Constraints & Risks** — 5 constraint categories, 10 assumptions, **8-risk register**, residual risk acceptance, 10 entropy defence mechanisms
- **Appendix A** — 3 CISO pitch variants (CISO Opening / Board / 30-Second) + 2 sub-variants (OEM / IT Security peer)
- **Appendix B** — Executive Dashboard Mockup (text + interactive HTML)

## Engagement context

- **Client:** Global EV cell manufacturing department ($1.2bn operation, $200M annual production value per department, 5 global sites)
- **Sponsor:** CISO as Executive Sponsor and Process Owner
- **MBB:** Olivia Key (Lean Six Sigma Master Black Belt in practice)
- **Team:** 19 Senior Software Engineers, certified as Green Belts
- **Same engagement** produced the Operational Stability Infrastructure (OSI) whitepaper — this is the cyber-domain extension of the same 4-layer framework (Layer 1 = hygiene, Layer 2 = visibility, Layer 3 = AI-augmented detection, Layer 4 = governance)

## Engagement status

| Phase | Status |
|---|---|
| Phase 1 (Define) | **Final — CISO G1 ready** |
| Phase 2 (Measure) | Pending G1 sign-off |
| Phase 3 (Analyse) | Pending G2 sign-off |
| Phase 4 (Improve) | Reference implementations complete (this repo) |
| Phase 5 (Control) | Standard Work + Kaizen + Maturity scoring defined (#6) |
| Continuation | Cross-site replication plan defined (Site 2-5 over 15 months) |

## Repository structure rationale

The repo is organised to match the engagement's logical flow:

- **`docs/01-charter/`** — what the client sees first (Phase 1 deliverable)
- **`docs/02-public-urls.md`** — the 3 live public deployments (CISO meeting pre-reads)
- **`docs/03-obsidian-note.md`** — the personal knowledge management note (in your Obsidian vault)
- **`implementation/`** — what the 19 Green Belts build (Phase 4 reference code)

The split is deliberate: **the charter is the deliverable; the implementation is the engine.** The client sees the charter; the engineering team uses the implementation; both are version-controlled here.

## Confidentiality

CONFIDENTIAL — CISO EYES ONLY. Anonymised per the Data-Access Protocol (#3.5 of the charter). Internal network configurations, IP addresses, hostnames, and proprietary system details are protected.

## License

This repository is licensed under the MIT License — see [`LICENSE`](LICENSE).
