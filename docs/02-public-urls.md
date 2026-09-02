# Live Public URLs

Three public deployments of this engagement are live, anonymised, and Six Sigma-aligned. This document records the URLs, node IDs, and the deployment pattern so the team can reproduce or update them.

## The 3 live URLs

| # | URL | Node ID | Purpose |
|---|---|---|---|
| 1 | https://87x1siaib1okk.space.minimax.io | 437417736610073 | **Full charter bundle** — 8 sections + 2 appendices + embedded dashboard (anonymised, Six Sigma aligned) |
| 2 | https://6z9fkk0oehsun.space.minimax.io | 437417949536415 | **Standalone CISO dashboard** (original deployment) — interactive 8-tile, click-to-drill-down |
| 3 | https://vmn4dy5p05641.space.minimax.io | 437426023305520 | **Standalone CISO dashboard** (additional deployment) — same content, separate URL |

## Use cases

- **URL 1** → use for the CISO meeting pre-read; the CISO can read the full document and click into the dashboard from within §7
- **URL 2** → use as a separate handout or live demo; the CISO opens just the dashboard, no other content; useful for showing only the visual artefact in a board context
- **URL 3** → backup, separate test environment, or clean URL for sharing with a different audience

## Deployment pattern

Each URL is published via the `website_deploy` tool. The pattern:

1. Verify the source file exists
2. Prepare a deploy directory with `index.html` at the root (rename source `.html` to `index.html` if needed)
3. Get **explicit user confirmation** before deploying (the tool requires it; deployment is public)
4. Use `project_name` as the human-readable name for the drive node + HTML `<title>`
5. Use `source_path` as the project source root (not inside the build path)
6. Save the returned `node_id` — pass it back to the same tool for in-place updates
7. Omit `node_id` to publish as a new site (new URL)

## Updating an existing deployment

To update an existing deployment with new content (e.g., after CISO re-baselines the target, or after Measure-phase data lands), pass the corresponding `node_id` to the next `website_deploy` call. The URL stays stable; the content is refreshed.

```python
# Example: update URL 1 with revised content
website_deploy(
    path="...path-to-new-index.html",
    project_name="Cyber Resilience Project Charter — Six Sigma Aligned",
    source_path="...project-source-root",
    node_id="437417736610073",  # updates URL 1 in place
)
```

## Publishing as a new deployment

To publish a separate, new site (different URL, fresh node), omit `node_id`. The existing URLs stay live. This was the pattern used for URL 3 (additional dashboard deployment).

## What's deployed

### URL 1 (full charter)

- **Content:** Cover page, document map/TOC, all 8 sections, Appendix A (3 pitch variants), Appendix B (dashboard mockup), embedded interactive CISO dashboard
- **Self-contained:** CSS + JS embedded; no external dependencies
- **Mobile-responsive:** layout collapses to single column at < 900px
- **Interactive:** click any of 8 dashboard tiles for drill-down
- **Size:** ~240 KB

### URL 2 and URL 3 (standalone dashboard)

- **Content:** Interactive 8-tile CISO Executive Dashboard only
- **State shown:** G5 illustrative, Six Sigma achieved (Z=6.0, all sub-processes Cpk ≥ 2.0)
- **Interactive:** click any tile to open drill-down modal with sub-metrics
- **Self-contained:** CSS + JS embedded; no external dependencies
- **Size:** ~44 KB each

## Confidentiality

All three deployments are **publicly accessible to anyone with the link**. The content is **anonymised per the Data-Access Protocol (§3.5 of the charter)**:

- ✓ No real IP addresses, hostnames, MAC addresses
- ✓ No vendor remote-access credentials
- ✓ No proprietary system configurations
- ✓ No identifying asset, person, or vendor information

The content includes:
- Five exposure classes with anonymised cost bands
- Cyber-FMEA with anonymised process step names
- Six Sigma-aligned capability targets
- Executive Dashboard with anonymised sample data
- CISO pitch variants (anonymised)

Anyone with the link can view this content. The internal implementation code (`../../implementation/`) is NOT deployed — that's for the 19 Green Belts only.

## When to update

- **After G1 sign-off** (CISO approves charter) → no update needed; the charter is the deliverable
- **After G2 sign-off** (capability baseline validated) → update dashboard with real baseline data
- **After G3 sign-off** (FMEA finalised) → update FMEA section with finalised RPNs
- **After G4 sign-off** (controls deployed) → update dashboard with G5 control plan
- **After G5 sign-off** (control plan live) → update dashboard with actual Z-score and Cpk values
- **If CISO requests a target change** → update sub-process capability targets
- **If a new high-RPN failure mode emerges** → update FMEA section

## Deployment log

| Date | URL | Node ID | Event |
|---|---|---|---|
| 2026-09-02 | https://87x1siaib1okk.space.minimax.io | 437417736610073 | Initial deployment of full charter bundle |
| 2026-09-02 | https://6z9fkk0oehsun.space.minimax.io | 437417949536415 | Initial deployment of standalone dashboard |
| 2026-09-02 | https://vmn4dy5p05641.space.minimax.io | 437426023305520 | Additional standalone dashboard deployment (separate URL) |
