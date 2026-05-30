# Prowler Reviewer

A standalone pentest review tool for Prowler OCSF JSON output (AWS, Azure, GCP).

## Quick Start

```bash
git clone <repo>
cd prowler-reviewer
docker compose up -d
```

Then open **http://localhost:8080** in your browser.

## Features

- **Upload** Prowler OCSF JSON output (drag & drop or file picker)
- **Consolidated findings** — one card per check title, all affected assets grouped
- **Advanced filters** — status, severity, cloud, subscription/account, resource group, service, analysis status
- **Analysis status** per finding — `To Report`, `Flagged`, `False Positive`, `Reported`
- **Auto-save** — state saved to Docker volume on every status change (debounced 1s)
- **State history** — up to 50 snapshots per project, restorable at any time
- **Markdown rendering** — risk details and remediation displayed as formatted code-style blocks
- **References** — remediation links and `unmapped.additional_urls` shown below remediation
- **Compliance controls** — collapsible list of benchmark control IDs
- **TSV copy** — copy filtered findings list or per-finding asset list for Excel
- **Stats dashboard** — counts + severity bar chart + pass/fail doughnut
- **Projects** — saved to Docker volume, reload without re-uploading JSON

## Architecture

```
frontend (nginx)  :8080  →  proxies /api/* to backend
backend (node)    :3001  →  reads/writes /data volume

/data/projects/{id}/
  raw.json        ← prowler JSON file
  state.json      ← current analysis state
  history/
    {timestamp}.json  ← state snapshots
```

## Data Privacy

- The Prowler JSON file is uploaded to the backend container and stored on the Docker volume only
- Nothing leaves the container
- No auth, no telemetry, no external calls

## Supported Prowler Output

Load the JSON OCSF output from Prowler:

```bash
prowler aws -M json-ocsf
prowler azure -M json-ocsf
prowler gcp -M json-ocsf
```

The output file (e.g. `prowler-output-*.ocsf.json`) can then be uploaded directly.
