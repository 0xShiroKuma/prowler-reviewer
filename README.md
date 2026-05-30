# Prowler Reviewer

A standalone cloud configuration review tool for Prowler OCSF JSON output (AWS, Azure, GCP).

## Quick Start

```bash
git clone <repo>
cd prowler-reviewer
docker compose up -d
```

Then open **http://localhost:8080** in your browser.

## Features

### Three-view workflow

| View | Purpose |
|------|---------|
| **Analysis** | Triage findings, set status, filter across all dimensions |
| **Compliance** | Benchmark-driven view grouped by control section and requirement |
| **Reporting** | Confirmed findings only, with copyable details/impact/remediation/assets sections |

### Upload & project preferences

- Drag & drop or pick a Prowler OCSF JSON file
- Select preferred benchmarks on import (CIS, C5, PCI, …)
- Preferred benchmarks are used as defaults in the Compliance and Reporting views
- Projects persist to a Docker volume — reload without re-uploading

### Analysis view

- **Multi-select filters** — OR within each filter, AND across filters (severity, status, analysis status, cloud, subscription/account, resource group, service, free-text search)
- **Consolidated findings** — one card per check, assets grouped under Failed / Passed sub-tabs
- **Check metadata enrichment** — Details, Impact, and Remediation sourced from `resources/check-metadata` (scan results still provide assets and pass/fail state)
- **Analysis status** per finding — `Confirmed`, `Flagged`, `False Positive`, `Reported`
- **Auto-save** — state saved on every change (debounced)
- **State history** — up to 50 snapshots per project, restorable at any time
- **TSV copy** — copy filtered findings list or per-tab asset list for Excel

### Compliance view

- Benchmark selector (preferred benchmarks listed first)
- Profile / level filter (CIS Level 1 / Level 2, C5 Basic / Additional, etc.)
- Requirements grouped by section and sub-section from the Prowler compliance catalog
- Each requirement shows **FAIL / PASS / N/A** status correlated from uploaded scan results
- Expand a requirement to see linked Prowler checks with Details / Impact / Remediation tabs (CIS Impact from compliance catalog for CIS benchmarks only)
- N/A checks link to the Prowler check hub when metadata is available
- Stats bar: total requirements, failed, passed, N/A

### Reporting view

- Shows only confirmed findings (`Confirmed` and `Reported`)
- Each finding rendered as expandable sections:
  - **Details** — check description from metadata, with 📋 Copy button
  - **Impact** — impact statement from metadata, with 📋 Copy button
  - **Remediation** — recommendation and procedure details from metadata, with 📋 Copy button
  - **Affected Assets** — failed assets only, TSV copy with `Affected {resource}` header (e.g. `Affected sites`)
  - **Controls** — preferred benchmark controls highlighted; other controls collapsed under "Other controls"

## Architecture

```
frontend (nginx)  :8080  →  proxies /api/* to backend
backend (node)    :3001  →  reads/writes /data volume
                          →  reads /compliance (bind-mounted catalog)
                          →  reads /check-metadata (bind-mounted Prowler check metadata)

/data/projects/{id}/
  raw.json        ← uploaded Prowler JSON
  state.json      ← analysis statuses + preferred benchmarks
  history/
    {timestamp}.json  ← state snapshots (max 50)
```

## Compliance catalog

The `resources/compliance/` directory contains Prowler's benchmark JSON files
(CIS, C5, PCI, NIST, ISO 27001, …) mounted read-only into the backend container.
These drive the Compliance view — every requirement is cross-referenced against
the uploaded scan results by matching `Requirements[].Checks[]` to Prowler
check IDs.

## Check metadata

The `resources/check-metadata/` directory contains Prowler check metadata files
(`*.metadata.json`) mounted read-only into the backend container. These provide
stable check content — title, description, impact, remediation procedures, and
resource type — used across Analysis, Compliance, and Reporting views.

Scan results remain the source for affected assets, pass/fail status, accounts,
resource groups, and reviewer analysis status.

## Data Privacy

- The Prowler JSON file is uploaded to the backend container and stored on the Docker volume only
- Nothing leaves the container
- No auth, no telemetry, no external calls

## Supported Prowler Output

```bash
prowler aws   -M json-ocsf
prowler azure -M json-ocsf
prowler gcp   -M json-ocsf
```

The output file (e.g. `prowler-output-*.ocsf.json`) can then be uploaded directly.
