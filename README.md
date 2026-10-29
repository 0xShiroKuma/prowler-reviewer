# Prowler Reviewer

A standalone cloud configuration review tool for Prowler OCSF JSON output (AWS, Azure, GCP).

## Quick Start

```bash
git clone <repo>
cd prowler-reviewer
docker compose up -d --build
```

Then open **http://localhost:8081** in your browser. The first visit asks you to create the account. Later visits ask you to sign in.

The visual identity reference, separate from the working tool, is at **http://localhost:8081/identity.html**.

The backend image build downloads the current compliance benchmarks and check metadata from the [Prowler](https://github.com/prowler-cloud/prowler) repository (`master` by default). Rebuild the backend image when you want newer frameworks or check text. Pin another tag or commit with `PROWLER_REF`:

```bash
PROWLER_REF=5.46.0 docker compose up -d --build
```

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
- **Consolidated findings** — one card per check, assets grouped under Failed / Passed / Manual sub-tabs
- **Check metadata enrichment** — Details, Impact, and Remediation sourced from the Prowler check metadata fetched at image build (scan results still provide assets and failed, passed, and manual state)
- **Analysis status** per finding — `Confirmed`, `Flagged`, `False Positive`, `Reported`
- **Custom findings** — add a finding that did not come from Prowler, with details, impact, remediation, assets, and linked benchmark controls
- **Auto-save** — state saved on every change (debounced)
- **State history** — up to 50 snapshots per project, restorable at any time
- **TSV copy** — copy filtered findings list or per-tab asset list for Excel

### Compliance view

- Benchmark selector (preferred benchmarks listed first)
- Profile / level filter (CIS Level 1 / Level 2, C5 Basic / Additional, etc.)
- Requirements grouped by section and sub-section from the Prowler compliance catalog
- Each requirement shows **FAIL / PASS / MANUAL / N/A** status correlated from uploaded scan results
- A separate **Review** status (`Pass`, `Fail`, `Manual`, `N/A`) records the pentester's own judgement. Set it to mark the control validated. Related controls on a finding use green for validated and amber for not validated
- Expand a requirement to see linked Prowler checks with Details / Impact / Remediation tabs (CIS Impact from compliance catalog for CIS benchmarks only)
- N/A checks link to the Prowler check hub when metadata is available
- Stats bar: total requirements, failed, passed, manual, N/A

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
frontend (nginx)  :8081  →  proxies /api/* to backend
backend (node)    :3001  →  reads/writes /data volume
                          →  reads /compliance (from the Prowler repo at image build)
                          →  reads /check-metadata (from the Prowler repo at image build)

/data/projects/{id}/
  raw.json             ← legacy projects only (created before multi-scan)
  scans/{scanId}.json  ← one OCSF file per scan
  state.json           ← reviewer statuses, reasons, notes, preferred benchmarks, and the scan list
  history/
    {timestamp}.json   ← state snapshots (max 50)

/data/auth/
  account.json         ← scrypt password hash, mode 0600
  sessions.json        ← SHA-256 of session tokens, not the tokens
  lockout.json         ← recent failed attempts
  audit.log            ← sign-in and password events, no secrets

/data/api/
  keys.json            ← SHA-256 of API tokens, expiry, project, and address list
  audit.log            ← key and review events, no tokens or note text
```

`state.scans` lists each file in order: id, original file name, time added, and `replaces`. `replaces` is null until a retest. A retest is another file; it names the scan it replaces and does not delete that file. Current evidence is every scan that no other scan replaces. One cloud keeps the Prowler check id, so two accounts share a card and existing reviewer fields still match. Two clouds use `<cloud>::<checkId>`, and reviewer fields are remapped once. Adding the same finding uid twice does not double the assets.

When a current scan has a predecessor, Analysis adds a Round filter: Still open, Closed, and New. It opens on Still open and New. A closed check keeps its reviewer status, note, and reason, and shows "Closed this round". Settings lists replaced scans without an upload-retest action. Remove deletes that one file.

## Compliance catalog and check metadata

Both catalogs are copied out of the Prowler git checkout while the backend image is built, so each rebuild follows the upstream files.

| Image path | Prowler source | Used for |
|------------|----------------|----------|
| `/compliance` | `prowler/compliance` | Benchmark JSON (CIS, C5, PCI, NIST, ISO 27001, …) |
| `/check-metadata` | `prowler/providers/**/*.metadata.json` | Check title, description, impact, remediation, resource type |

The Compliance view cross-references every requirement against the uploaded scan by matching requirement checks to Prowler check IDs. That includes the original per-cloud benchmark files and the newer multi-cloud frameworks Prowler publishes at the catalog root. Analysis, Compliance, and Reporting all read the same check metadata.

`GET /api/catalog` reports the Prowler repo, ref, commit, and file counts baked into the running image. Docker rebuilds the catalog step when that git ref points at a new commit. Restarting the container without a rebuild keeps the catalogs from the current image.

Scan results remain the source for affected assets, failed, passed, and manual status, accounts, resource groups, and reviewer analysis status. A project can hold several scans; a retest compares the latest file with the one it replaced.

## Authentication

One account per installation. It is created in the browser on first launch, then every visit requires a sign-in. There is no second user and no online password reset.

- The only password rule is a minimum of 5 characters. Common passwords are allowed.
- Passwords are hashed with scrypt (N=2^17, r=8, p=1, 16-byte salt) and stored on the data volume. The password itself is not stored.
- Checking the password takes a couple of seconds. That delay is the hash, not a stuck page.
- The session cookie is `HttpOnly` and `SameSite=Strict`. The server stores only a SHA-256 of the token. A session ends after 12 hours idle or 7 days, whichever comes first.
- Sign-in is limited to 5 failures per 15 minutes. The failure message is the same for an unknown username and a wrong password.
- State-changing requests must send `X-Requested-With: prowler-reviewer` and, for JSON, `Content-Type: application/json`.
- Set `COOKIE_SECURE=1` on the backend when the site is served over HTTPS. Leave it unset for plain HTTP on localhost, or the browser will not send the cookie.
- The published port listens on this machine only (`127.0.0.1:8081`).
- Anyone who can run commands in the backend container can reset the password. Treat Docker access as root access to this app.

A signed-in user can change the password from the **Password** button. That signs every session out.

### Lost password

Recovery is a break-glass action on the machine that runs Docker. From the project directory:

```bash
docker compose exec -u root -it backend node reset-password.js
```

The command prompts for a new password, does not echo it, does not accept the password as an argument, replaces the hash, clears the sign-in lockout, and signs out every session. Confirm the username in the output. The new password is not printed or written to the audit log.

When there is no terminal, pass the password on stdin instead of the command line:

```bash
docker compose exec -u root -T backend node reset-password.js --password-stdin
```

If the account file is missing, add `--username <name>` to create it from the container.

Sign-in and password events are appended to `/data/auth/audit.log` inside the volume. Read them with:

```bash
docker compose exec -u root backend tail -n 50 /data/auth/audit.log
```

## Review API

A signed-in user can create a key from **API** in the header. Harnesses such as Cursor or Codex call this HTTP API directly. It is not an MCP server, and it does not accept the browser session.

The OpenAPI 3.0 contract is [docs/openapi.yaml](docs/openapi.yaml). Load that file in Swagger UI, Redoc, or any OpenAPI tool. The harness context, with the same operations and no review instructions, is [docs/agent-api.md](docs/agent-api.md).

The token is shown once. The server stores only its SHA-256. A key is bound to one project, expires on the date you set (90 days at most), and can be limited to a list of IP addresses or CIDR ranges. The form starts with `127.0.0.1` and `::1`. Those entries also allow the Docker bridge address, so a harness on the same machine can call the published port. Clear the list to allow every address that can reach this app.

Send the token on every request:

```bash
curl -s http://localhost:8081/api/v1 \
  -H "Authorization: Bearer prk_…"
```

`GET /api/v1` describes the project and the selected benchmarks. From there:

| Method | Path | What it does |
|---|---|---|
| GET | `/api/v1/findings` | Prowler findings and custom findings. Each one has the scanner result, the pentester status, the false-positive reason, the note, and whether the pentester has touched it. |
| GET | `/api/v1/findings/:id` | The same finding, including details, impact, remediation, and assets. |
| POST | `/api/v1/findings` | Create a custom finding. Requires a write key. |
| PATCH | `/api/v1/findings/:id` | Set status, reason, and note. A write key can also edit the text, assets, and linked controls. On a scan finding that edit is a review copy; the uploaded scan stays unchanged. |
| DELETE | `/api/v1/findings/:id` | Delete a custom finding. Prowler findings stay. |
| GET | `/api/v1/benchmarks` | Benchmarks selected for the project. |
| GET | `/api/v1/controls` | Requirements for those benchmarks, with the scanner result and the pentester's validation. `?benchmark=` reads one framework, including one that is not selected. `?validated=false` lists controls that have not been reviewed. |
| PATCH | `/api/v1/controls` | Set a control's review status (`pass`, `fail`, `manual`, `n/a`, or `""`) and an optional note. |

A finding is **touched** when it has a status, a false-positive reason, or a note, or when it was created in this tool. A control is **validated** when its review status is set. Scanner pass, fail, and manual results stay as the scan reported them.

Filters on the findings list: `touched`, `status`, `scanner` (`fail`, `pass`, `manual`), `source` (`prowler` or `custom`), `q`, `limit`, and `offset`.

Write requests use `Content-Type: application/json`. A read-only key can look but gets `403` if it tries to change anything. Requests are limited per key. Failed keys are limited per address. Revoking a key in the UI stops it immediately.

The key cannot delete the project, upload scans, restore history, or create other keys. Do not publish the backend port. The address list trusts the address nginx records, so a client that can reach the backend directly could claim a different address.

## Data Privacy

- The Prowler JSON file is uploaded to the backend container and stored on the Docker volume only
- Scan data and the password hash stay on that volume
- Compliance benchmarks and check metadata are downloaded from the public Prowler GitHub repository during the image build only
- No telemetry and no external calls while the app is running

## Supported Prowler Output

```bash
prowler aws   -M json-ocsf
prowler azure -M json-ocsf
prowler gcp   -M json-ocsf
```

The output file (e.g. `prowler-output-*.ocsf.json`) can then be uploaded directly.
