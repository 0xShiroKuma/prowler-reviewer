# Prowler Reviewer API

This file is the context for calling the Prowler Reviewer HTTP API. It describes the records the tool stores and the calls that read and write them. Which status to set, and what to write in a finding, comes from your own instructions.

The same contract is [openapi.yaml](openapi.yaml) (OpenAPI 3.0). Load that file in Swagger UI, Redoc, or any OpenAPI tool.

## Tool

Prowler Reviewer is a local app. A person uploads a Prowler OCSF scan, selects benchmarks, and reviews the result in the browser. Your key is bound to one project. Paths do not take a project id.

Call the app origin. The default local origin is `http://localhost:8081`. The path prefix is `/api/v1`. Do not call the backend port. The address check uses the address nginx records for the connection.

A person creates the key in the app under **API**, sets an expiry (90 days at most), and an IP allowlist. The form starts with `127.0.0.1` and `::1`. Those entries also allow the Docker bridge gateway, which is the address this app sees for a harness on the same machine. An empty allowlist allows every address. The token is shown once. You cannot create, list, or revoke keys. You cannot upload a scan, delete the project, or restore history. A successful write does store a history snapshot.

Send the token on every request:

```http
Authorization: Bearer prk_…
```

The token is `prk_` plus 43 base64url characters. A browser session cookie is rejected. There is no CSRF header on `/api/v1`.

`GET /api/v1` returns `scopes`. `read` can call every GET. `write` is required for POST, PATCH, and DELETE. A read-only key that tries to write receives `403` and `This key cannot change data.`

## Records

Three records are separate. Writing one does not change the others.

**Scanner result.** Counts and statuses taken from the Prowler scan. A finding has `scanner.fail`, `scanner.pass`, and `scanner.manual`. A benchmark control has `scannerStatus` and the same three counts, summed from the Prowler checks listed in that requirement. `scannerStatus` is `fail` when any linked check has a fail count, otherwise `pass`, otherwise `manual`, otherwise `n/a`. Custom findings do not change those control counts.

**Finding review.** `review.status`, `review.reason`, and `review.note` on a finding. `review.touched` is true when any of those is set, or when `source` is `custom`. `reason` is the text stored with the finding. The UI labels that field as the false-positive reason. The API stores the string you send.

**Control review.** `review.status` and `review.note` on a benchmark requirement. `review.validated` is true when the status is not empty. This is a different note from the finding note.

Finding status is one of `""`, `confirmed`, `flagged`, `false-positive`, `reported`. Control status is one of `""`, `pass`, `fail`, `manual`, `n/a`. An empty string clears that field. Severity is `critical`, `high`, `medium`, `low`, or `informational`.

`source` is `prowler` or `custom`. Use the `id` returned by the API. A Prowler id is the check id. When the project contains more than one cloud, that id is `<cloud>::<check id>`. A custom id is `custom_` plus 32 hex characters, assigned by the server.

`round` on a finding or asset is empty, `open`, `closed`, or `new` when the project has a retest baseline. `assets[].absent` is true when a previously failing asset is no longer in the latest scan.

`scanControls` is a list of strings copied from the scan, shaped like `CIS: 1.20`. `controls` on a finding is the list of related benchmark requirements, with each requirement's scanner status and review. On a read, that list is built from the project's selected benchmarks. A custom finding's stored links are also returned on the detail object as `custom.controls`, including a benchmark that is not selected.

A control's `findings` array lists the Prowler checks mapped by the benchmark and the custom findings linked to that requirement.

`GET /api/v1/controls?benchmark=<id>` reads any benchmark in the server catalog, including one the project has not selected. Copy `benchmarkId` and `requirementId` from that response when you link or review a control. A benchmark id does not contain `..`. A requirement id does not contain `::` and is at most 80 characters.

## Calling

JSON writes send `Content-Type: application/json`. The largest `/api/v1` body is 256 KB.

Filters on `GET /api/v1/findings` combine with AND:

| Query | Values | Effect |
|---|---|---|
| `touched` | `true`, `false` | `review.touched` |
| `status` | `confirmed`, `flagged`, `false-positive`, `reported` | Exact `review.status`. Omitting it returns every status, including empty. |
| `scanner` | `fail`, `pass`, `manual` | That scanner count is greater than zero |
| `source` | `prowler`, `custom` | Finding source |
| `q` | text | Case-insensitive substring of title, id, or service. 200 characters are used. |
| `limit` | 1–200 | Page size. Default 100. |
| `offset` | 0 or more | Default 0. |

The list is ordered by severity from critical to informational, then by failing asset count. The list includes `review.reason` and `review.note`. It omits details, impact, remediation, observations, and the asset list. `failedAssetNames` holds the first 25 failing asset names, and `failedAssetCount` is the full count. `nextOffset` is the next `offset`, or `null` on the last page. `total` is the filtered count.

`GET /api/v1/controls` accepts `validated=true` or `validated=false`.

Errors are JSON `{ "error": "..." }`:

| Status | When |
|---|---|
| 400 | A field was rejected, the JSON is invalid, or a Prowler finding was given content fields or DELETE. |
| 401 | The key is missing, malformed, unknown, or expired. |
| 403 | The address is outside the allowlist, or the key has no write scope. |
| 404 | The project, finding, benchmark, or control does not exist. |
| 413 | The body is larger than 256 KB. |
| 415 | A write did not use `Content-Type: application/json`. |
| 429 | 120 reads per key per minute, 30 writes per key per minute, or 30 failed authentications per address per 15 minutes. `Retry-After` is seconds. |
| 500 | Unexpected server error. |

Known 400 texts include `Unknown finding status.`, `Unknown severity.`, `A custom finding needs a title.`, `Add at least one asset.`, `Each asset needs a name.`, `Asset status must be FAIL, PASS, or MANUAL.`, `Controls must be a list.`, `A control needs a benchmark id and a requirement id.`, `Benchmark not found: …`, `Control … is not in …`, `Prowler findings only accept status, reason, and note.`, `Prowler findings cannot be deleted.`, and `Unknown control status. Use pass, fail, manual, n/a, or an empty string.`

## GET /api/v1

Returns the project, the selected benchmarks, the key scope, and the expiry.

```json
{
  "project": {
    "id": "proj_…",
    "name": "Demo",
    "updatedAt": "2026-10-28T09:00:00.000Z",
    "benchmarks": [
      { "id": "aws/cis_1.5_aws", "name": "CIS AWS", "framework": "CIS", "version": "1.5", "provider": "AWS" }
    ]
  },
  "scopes": ["read", "write"],
  "expiresAt": "2026-11-27T13:59:59.000Z",
  "key": { "id": "key_…", "name": "cursor", "prefix": "prk_abc12345" },
  "review": {
    "touched": "A finding is touched when it has a pentester status, false-positive reason, or note, or when it was created in this tool.",
    "validated": "A benchmark control is validated when the pentester has set its review status in Compliance."
  }
}
```

## GET /api/v1/findings

```http
GET /api/v1/findings?touched=false&scanner=fail&limit=100&offset=0
```

```json
{
  "total": 1,
  "offset": 0,
  "limit": 100,
  "nextOffset": null,
  "findings": [
    {
      "id": "accessanalyzer_enabled",
      "source": "prowler",
      "title": "Access Analyzer",
      "severity": "medium",
      "cloud": "aws",
      "service": "accessanalyzer",
      "round": "",
      "scanner": { "fail": 1, "pass": 0, "manual": 0 },
      "review": { "status": "", "reason": "", "note": "", "touched": false },
      "scanControls": ["CIS: 1.20"],
      "controls": [
        {
          "benchmarkId": "aws/cis_1.5_aws",
          "benchmark": "CIS AWS",
          "requirementId": "1.20",
          "description": "Ensure IAM Access Analyzer is enabled",
          "scannerStatus": "fail",
          "validated": false,
          "reviewStatus": "",
          "note": ""
        }
      ],
      "failedAssetNames": ["analyzer"],
      "failedAssetCount": 1
    }
  ]
}
```

## GET /api/v1/findings/{id}

The list object, plus `details`, `impact`, `remediation`, `observations`, and `assets`. A custom finding also has `custom`.

```json
{
  "id": "custom_0123456789abcdef0123456789abcdef",
  "source": "custom",
  "details": "The role grants administrator access.",
  "impact": "A stolen key can change the account.",
  "remediation": "Remove the unused policy.",
  "observations": [],
  "assets": [
    {
      "name": "arn:aws:iam::123456789012:role/Admin",
      "status": "FAIL",
      "region": "us-east-1",
      "service": "",
      "subscription": "",
      "resourceGroup": "",
      "round": "",
      "absent": false
    }
  ],
  "custom": {
    "cloud": "aws",
    "service": "iam",
    "controls": [
      { "benchmarkId": "aws/cis_1.5_aws", "requirementId": "1.16", "label": "" }
    ]
  }
}
```

Asset `status` on a stored custom finding is `FAIL`, `PASS`, or `MANUAL`. Omitted status is stored as `FAIL`.

## POST /api/v1/findings

Write scope. Creates a custom finding and returns the detail object with `201`.

Required: `title` (1–200 characters) and `assets` (1–100 items, each with `name`, 1–300 characters). Optional: `severity` (default `medium`), `cloud` (default `Custom`, max 40), `service` (max 120), `status`, `reason` (max 16000), `note` (max 16000), `details`, `impact`, `remediation` (each max 16000), `observations` (max 20 strings, 4000 each), `controls` (max 40).

Each control is `{ "benchmarkId", "requirementId", "label" }`. `label` is optional and max 240 characters. The benchmark and requirement must exist in the catalog. The project keeps at most 200 custom findings.

```json
{
  "title": "Unused administrative access",
  "severity": "high",
  "cloud": "aws",
  "service": "iam",
  "status": "",
  "reason": "",
  "note": "",
  "details": "The role grants administrator access and has not been used.",
  "impact": "A stolen key can change the account.",
  "remediation": "Remove the unused policy.",
  "observations": [],
  "assets": [
    { "name": "arn:aws:iam::123456789012:role/Admin", "status": "FAIL", "region": "us-east-1" }
  ],
  "controls": [
    { "benchmarkId": "aws/cis_1.5_aws", "requirementId": "1.16" }
  ]
}
```

## PATCH /api/v1/findings/{id}

Write scope. Returns the detail object. Omitted fields stay as they are. Send `""` to clear `status`, `reason`, or `note`.

On a Prowler finding, the body may contain only `status`, `reason`, and `note`.

On a custom finding, the body may also contain `title`, `severity`, `cloud`, `service`, `details`, `impact`, `remediation`, `observations`, `assets`, and `controls`. A field you send replaces the stored value. After the merge, the finding still needs a title and at least one named asset, and every control must exist in the catalog.

```json
{ "status": "flagged", "reason": "", "note": "Checked against the account alias." }
```

## DELETE /api/v1/findings/{id}

Write scope. Removes a custom finding and clears its status, reason, and note. Response is `{ "ok": true }`. A Prowler id returns 400.

## GET /api/v1/benchmarks

Selected benchmarks, each with a `requirements` count.

```json
{
  "benchmarks": [
    {
      "id": "aws/cis_1.5_aws",
      "name": "CIS AWS",
      "framework": "CIS",
      "version": "1.5",
      "provider": "AWS",
      "requirements": 1
    }
  ]
}
```

## GET /api/v1/controls

Selected benchmarks, or one catalog benchmark when `benchmark` is set. `validated=true` keeps controls with a review status. `validated=false` keeps controls with an empty review status.

```http
GET /api/v1/controls?benchmark=aws/cis_1.5_aws&validated=false
```

```json
{
  "benchmarks": [
    {
      "benchmark": {
        "id": "aws/cis_1.5_aws",
        "name": "CIS AWS",
        "framework": "CIS",
        "version": "1.5",
        "provider": "AWS",
        "selected": true
      },
      "controls": [
        {
          "id": "1.20",
          "description": "Ensure IAM Access Analyzer is enabled",
          "section": "Identity",
          "subsection": "",
          "profile": "Level 1",
          "checks": ["accessanalyzer_enabled"],
          "scannerStatus": "fail",
          "failCount": 1,
          "passCount": 0,
          "manualCount": 0,
          "review": { "status": "", "note": "", "validated": false, "updatedAt": null },
          "findings": [
            {
              "id": "accessanalyzer_enabled",
              "source": "prowler",
              "title": "Access Analyzer",
              "reviewStatus": "",
              "reason": "",
              "note": "",
              "touched": false,
              "failCount": 1,
              "passCount": 0,
              "manualCount": 0
            }
          ]
        }
      ]
    }
  ]
}
```

## PATCH /api/v1/controls

Write scope. Returns the control object above. `benchmarkId` and `requirementId` are required. `status` and `note` are optional; an omitted field keeps its current value. `note` is at most 8000 characters. When the stored status and note are both empty, the review is removed and `validated` is false. At most 2000 control reviews are kept.

```json
{
  "benchmarkId": "aws/cis_1.5_aws",
  "requirementId": "1.20",
  "status": "fail",
  "note": "Analyzer is disabled in this region."
}
```

To clear a review, send `"status": ""` and `"note": ""`.
