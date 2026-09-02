# Executive Dashboard Specifications

The CISO Executive Dashboard is the continuous visibility tool (§7.2 of the charter). 8 tiles, structured to map the engagement's key metrics. This specification defines the data sources, refresh cadence, alert thresholds, and access controls for each tile.

## Charter reference

§7.2 Executive Dashboard.

## Dashboard structure

```
┌──────────────────────────────────────────────────────────────────────┐
│  EV CELL CYBER RESILIENCE — EXECUTIVE DASHBOARD                       │
│  Anonymised | Z-Score (target ≥ 6.0) | Last Refresh: [timestamp]     │
│  Status: GREEN/AMBER/RED                                              │
├───────────────────────────────────┬──────────────────────────────────┤
│                                   │                                  │
│  TILE 1: PROCESS CAPABILITY       │  TILE 2: FINANCIAL EXPOSURE      │
│  (Z-Score, Cpk)                    │  (COPQ, Protected Value)         │
│                                   │                                  │
├───────────────────────────────────┼──────────────────────────────────┤
│                                   │                                  │
│  TILE 3: VELOCITY METRICS         │  TILE 4: RISK MITIGATION         │
│  (MTTD, MTTR)                      │  (FMEA, patch, vendor)            │
│                                   │                                  │
├───────────────────────────────────┼──────────────────────────────────┤
│                                   │                                  │
│  TILE 5: KAIZEN ACTIVITY          │  TILE 6: MATURITY SCORE          │
│  (triggers, A3s)                   │  (Level 3-4)                      │
│                                   │                                  │
├───────────────────────────────────┼──────────────────────────────────┤
│                                   │                                  │
│  TILE 7: CROSS-SITE STATUS        │  TILE 8: REGULATORY & COMPLIANCE │
│  (per-site maturity)               │  (NIS2, IEC 62443, OEM)          │
│                                   │                                  │
└───────────────────────────────────┴──────────────────────────────────┘
```

## Tile 1: Process Capability

**Metrics:**
- Engagement Z-Score (line, 12-week trend)
- Per-sub-process Cpk (bar chart)
- Target line at Z = 6.0 (theoretical Six Sigma)

**Data source:** `capability_metrics` table in the anonymised data lake

**Refresh:** Daily

**Alert thresholds:**
- GREEN: Z ≥ 6.0, all sub-processes Cpk ≥ 2.0
- AMBER: 5.5 ≤ Z < 6.0 OR any sub-process Cpk < 2.0
- RED: Z < 5.5 OR engagement paused

**Access:** CISO (full), MBB (full), Track Leads (their track's sub-processes), Operations Director (engagement Z only)

## Tile 2: Financial Exposure

**Metrics:**
- COPQ Avoided YTD ($M)
- Protected Value Realised ($M, vs §2.5 model)
- E_cyber band trend
- Per-event cost avoided breakdown (downtime, silent corruption, IP, regulatory)

**Data source:** `financial_exposure` table (computed by MBB from incident data); `response_events` (for COPQ calc)

**Refresh:** Weekly (financial data) + Daily (incident counts)

**Alert thresholds:**
- GREEN: Protected value realisation ≥ 50% of conservative model
- AMBER: 25% ≤ realisation < 50%
- RED: realisation < 25% OR COPQ avoided YTD < $1M

**Access:** CISO (full), MBB (full), Operations Director (full), Finance (full)

## Tile 3: Velocity Metrics

**Metrics:**
- MTTD known signatures (target ≤ 2 min, Six Sigma)
- MTTD novel OT anomalies (target ≤ 10 min, AI-augmented)
- MTTR hard stop (target ≤ 1 hour, Six Sigma)
- MTTR OT compromise (target ≤ 8 hours, Six Sigma)
- Drill results (last 3 monthly drills)
- AI agent status (operational / killed / performance degraded)

**Data source:** `detection_events` and `response_events` tables; AI agent health() method

**Refresh:** Daily

**Alert thresholds:**
- GREEN: all metrics within target
- AMBER: any sub-process MTTD or MTTR exceeds target by ≤ 20%
- RED: any sub-process exceeds target by > 20%, OR any AI agent killed, OR real-time incident triggered

**Access:** CISO (full), MBB (full), Track Leads (their track's metrics), Operations Director (full), IT Security (AI agent status)

## Tile 4: Risk Mitigation

**Metrics:**
- Top 10 FMEA RPN trend (line chart, 12-week)
- Top RPN (RPN value, mode description)
- RPN reduction vs pre-engagement (target ≥ 80%, Six Sigma)
- Patch compliance % (target ≥ 99%, Six Sigma)
- Vendor access compliance % (target = 100%)
- FMEA last refresh date (target: quarterly)
- Open audit findings (target = 0)

**Data source:** `fmea_register` and `patch_compliance` tables

**Refresh:** Daily (compliance), Quarterly (FMEA)

**Alert thresholds:**
- GREEN: RPN reduction ≥ 80%, patch compliance ≥ 99%, vendor compliance = 100%
- AMBER: 60% ≤ RPN reduction < 80%, OR 95% ≤ patch < 99%
- RED: RPN reduction < 60%, OR patch < 95%, OR any audit finding open

**Access:** CISO (full), MBB (full), Track Leads (their track's FMEA section), Safety Officer (Severity = 10 rows), Operations Director (full), Legal/Compliance (audit findings)

## Tile 5: Kaizen Activity

**Metrics:**
- Open Kaizens (count, by trigger)
- Closed Kaizens YTD (count)
- A3 close-out time distribution (median, P90)
- Trigger frequency (count by trigger, YTD)
- Trigger catalogue (13 triggers with current status)

**Data source:** `kaizen_events` table

**Refresh:** Daily

**Alert thresholds:**
- GREEN: A3 close-out median ≤ 5 BD, no open Kaizens > 5 BD
- AMBER: A3 close-out median > 5 BD, OR any open Kaizen > 5 BD
- RED: any open Kaizen > 10 BD, OR Tier 3 escalation triggered (structural change)

**Access:** CISO (full), MBB (full), Track Leads (their track's Kaizens), Operations Director (full), Legal/Compliance (regulatory Kaizens)

## Tile 6: Maturity Score

**Metrics:**
- Current Level (1-5)
- Sub-indicator scores (0-2 each, 8 sub-indicators)
- Total score (out of 16)
- Trend (improving / stable / declining)
- External validation status (when available)
- Regression alerts (any sub-indicator dropped since last quarter)

**Data source:** `maturity_scores` table; computed by MBB quarterly

**Refresh:** Quarterly

**Alert thresholds:**
- GREEN: Level 4-5, no regression
- AMBER: Level 3, OR any sub-indicator regression
- RED: Level 2, OR ≥ 2 sub-indicator regressions

**Access:** CISO (full), MBB (full), Track Leads (their track's sub-indicators), Operations Director (full)

## Tile 7: Cross-Site Status

**Metrics:**
- Per-site: maturity level, Z-score, replication phase
- Replication timeline: Site 2-5 progress
- Knowledge transfer cadence
- Cross-site audit exchange status

**Data source:** `maturity_scores` (per-site); site MBB reporting

**Refresh:** Monthly (post-replication start; M4+)

**Alert thresholds:**
- GREEN: all sites at Level 4+, replication on schedule
- AMBER: any site at Level 3, OR replication delayed by ≤ 1 month
- RED: any site at Level 2, OR replication delayed by > 1 month

**Access:** CISO (full), MBB (full), Site MBBs (their site only), Operations Director (full)

## Tile 8: Regulatory & Compliance

**Metrics:**
- NIS2 (EU) status (Compliant / Non-compliant)
- IEC 62443 status
- OEM cyber attestation (per major OEM: VW, BMW, Stellantis, others)
- GDPR (where personal data is in scope)
- EU PLD 2024/2853 (structural controls operational)
- Open audit findings (count)
- Pending regulatory changes (count)
- OEM renewals due in 90 days (count)

**Data source:** MBB + Legal/Compliance + CISO regulatory log

**Refresh:** Monthly (regulatory cadence), Quarterly (audit findings)

**Alert thresholds:**
- GREEN: all frameworks compliant, 0 audit findings
- AMBER: any pending regulatory change, OR 1-2 OEM renewals due
- RED: any non-compliance finding, OR > 2 OEM renewals overdue, OR Tier 3 escalation (regulatory disclosure)

**Access:** CISO (full), MBB (full), Legal/Compliance (full), Operations Director (summary)

## Color coding

- 🟢 **GREEN:** all metrics within target, standard cadence
- 🟡 **AMBER:** one or more sub-metrics outside target, escalated review
- 🔴 **RED:** engagement-level issue, CISO notified within 4 hours, emergency briefing within 24 hours

## Common interface

```python
Tile.render() -> TileRender
Tile.get_status() -> "GREEN" | "AMBER" | "RED"
Tile.drill_down(metric_id: str) -> DrillDownView
```

## Properties

- **Real-time where possible:** SPC charts refresh automatically
- **Bounded queries:** each tile query has max_rows and timeout_sec
- **Drill-down:** click any metric to view source data (anonymised)
- **Mobile-responsive:** works on tablet/phone
- **Audit-logged:** every dashboard view is logged
- **Print-friendly:** can be saved as PDF for CISO meeting handout

## Reference implementation

The reference dashboard is the existing HTML mockup at `deliverables/ciso-dashboard-mockup.html` (already deployed publicly). The production dashboard replaces the mockup with:

- **Real data sources:** the 8 tiles query the anonymised data lake
- **Real-time refresh:** automated daily/weekly/monthly/quarterly refresh
- **Drill-down to source:** each tile's drill-down links to the data lake
- **AI agent health integration:** Tile 3 and Tile 5 read AI agent health() outputs

The production implementation can use:
- Streamlit (Python, easy, integrates with the data lake)
- Plotly Dash (Python, more customisable)
- React + D3.js (most flexible, requires more build effort)

## Deployment

- Track B (Data & Metrics) builds the production dashboard
- Reads from the anonymised data lake (bypasses the query interface for performance)
- Hosted on the corporate BI environment
- Accessible to authorised stakeholders per the access matrix above
- Tested in Weeks 11-12; deployed for G5

## Performance targets

- Initial dashboard load ≤ 3 seconds
- Tile refresh ≤ 1 second (each tile)
- Drill-down response ≤ 2 seconds
- Uptime ≥ 99.5%
- Mobile response time ≤ 5 seconds
