'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const dataRoot = path.join(__dirname, '..', 'data');
fs.mkdirSync(dataRoot, { recursive: true });
const tmp = fs.mkdtempSync(path.join(dataRoot, 'agent-test-'));
const compliance = path.join(tmp, 'compliance');
process.env.DATA_DIR = tmp;
process.env.COMPLIANCE_DIR = compliance;
process.env.CHECK_METADATA_DIR = path.join(tmp, 'meta');
delete process.env.COOKIE_SECURE;

const { app } = require('./server');
const { ipAllowed, parseAllow, clientAllowed, gatewayFromRoute } = require('./agent');

const USER = 'reviewer';
const PASS = 'correct-horse-battery';

function cookieHeader(setCookie) {
  const line = (setCookie || []).find(value => value.startsWith('pr_session='));
  return line ? line.split(';')[0] : '';
}

async function call(base, method, urlPath, { body, cookie, csrf = true, token, headers = {} } = {}) {
  const reqHeaders = { ...headers };
  if (csrf && method !== 'GET' && method !== 'HEAD') reqHeaders['X-Requested-With'] = 'prowler-reviewer';
  if (body !== undefined) reqHeaders['Content-Type'] = 'application/json';
  if (cookie) reqHeaders.Cookie = cookie;
  if (token) reqHeaders.Authorization = `Bearer ${token}`;
  const res = await fetch(base + urlPath, {
    method,
    headers: reqHeaders,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = null; }
  const setCookie = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
  return { status: res.status, json, text, setCookie };
}

test('address lists match an address or a range', () => {
  const slash8 = parseAllow('10.0.0.0/8');
  assert.equal(ipAllowed([slash8], '10.1.2.3'), true);
  assert.equal(ipAllowed([slash8], '11.0.0.1'), false);
  assert.equal(ipAllowed([parseAllow('203.0.113.9')], '203.0.113.9'), true);
  assert.equal(ipAllowed([parseAllow('203.0.113.9')], '203.0.113.10'), false);
  assert.equal(ipAllowed([], '192.0.2.1'), true);
  assert.equal(parseAllow('not a host'), null);
  const v6 = parseAllow('2001:db8::/32');
  assert.equal(ipAllowed([v6], '2001:db8::1'), true);
  assert.equal(ipAllowed([v6], '2001:db9::1'), false);

  const local = [parseAllow('127.0.0.1'), parseAllow('::1')];
  assert.equal(clientAllowed(local, '127.0.0.1', ['172.22.0.1']), true);
  assert.equal(clientAllowed(local, '::1', ['172.22.0.1']), true);
  assert.equal(clientAllowed(local, '172.22.0.1', ['172.22.0.1']), true);
  assert.equal(clientAllowed(local, '203.0.113.9', ['172.22.0.1']), false);
  assert.equal(clientAllowed([parseAllow('203.0.113.9')], '172.22.0.1', ['172.22.0.1']), false);
  assert.equal(gatewayFromRoute('Iface Destination Gateway Flags\neth0 00000000 010016AC 0003\n'), '172.22.0.1');
});

test('agent api', { timeout: 180000 }, async () => {
  fs.mkdirSync(path.join(compliance, 'aws'), { recursive: true });
  fs.writeFileSync(path.join(compliance, 'aws', 'cis_test.json'), JSON.stringify({
    Framework: 'CIS',
    Name: 'CIS AWS',
    Version: '1.5',
    Provider: 'AWS',
    Requirements: [{
      Id: '1.20',
      Description: 'Ensure IAM Access Analyzer is enabled',
      Checks: ['accessanalyzer_enabled'],
      Attributes: [{ Section: 'Identity', Profile: 'Level 1' }]
    }]
  }));

  const projectId = 'proj_agent';
  const otherId = 'proj_other';
  const scan = [{
    finding_info: {
      uid: 'prowler-aws-accessanalyzer_enabled-account',
      title: 'Access Analyzer',
      check_id: 'accessanalyzer_enabled'
    },
    status_code: 'FAIL',
    severity: 'Low',
    status_detail: 'IAM Access Analyzer is not enabled.',
    cloud: { provider: 'aws', account: { name: 'prod' }, region: 'us-east-1' },
    resources: [{ name: 'analyzer', region: 'us-east-1' }],
    unmapped: { compliance: { 'CIS-1.5': ['1.20'] } }
  }];
  for (const id of [projectId, otherId]) {
    const dir = path.join(tmp, 'projects', id, 'scans');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'scan_1.json'), JSON.stringify(scan));
    fs.writeFileSync(path.join(tmp, 'projects', id, 'state.json'), JSON.stringify({
      name: id === projectId ? 'Demo' : 'Other client',
      preferredBenchmarks: ['aws/cis_test'],
      scans: [{ id: 'scan_1', label: 'scan.json', addedAt: '2026-01-01T00:00:00.000Z', replaces: null }],
      statuses: { accessanalyzer_enabled: 'false-positive' },
      reasons: { accessanalyzer_enabled: 'The account is a lab.' },
      notes: { accessanalyzer_enabled: 'Mention the lab in the report.' },
      customFindings: [],
      controlReviews: {}
    }));
  }

  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  try {
    const created = await call(base, 'POST', '/api/auth/register', { body: { username: USER, password: PASS } });
    assert.equal(created.status, 201);
    const cookie = cookieHeader(created.setCookie);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    const noCsrf = await call(base, 'POST', '/api/access', {
      csrf: false,
      cookie,
      body: { name: 'harness', projectId, expiresAt, write: true }
    });
    assert.equal(noCsrf.status, 403);

    const sessionOnly = await call(base, 'GET', '/api/v1/findings', { cookie });
    assert.equal(sessionOnly.status, 401);

    const minted = await call(base, 'POST', '/api/access', {
      cookie,
      body: { name: 'harness', projectId, expiresAt, write: true, ipAllowlist: ['127.0.0.1'] }
    });
    assert.equal(minted.status, 201, minted.text);
    const token = minted.json.token;
    assert.match(token, /^prk_/);
    assert.equal(minted.json.key.prefix.length > 0, true);

    const listed = await call(base, 'GET', '/api/access', { cookie });
    assert.equal(listed.json.keys.length, 1);
    assert.equal(JSON.stringify(listed.json).includes(token), false);
    const stored = fs.readFileSync(path.join(tmp, 'api', 'keys.json'), 'utf8');
    assert.equal(stored.includes(token), false);

    const blockedIp = await call(base, 'GET', '/api/v1/findings', {
      token,
      headers: { 'X-Real-IP': '203.0.113.9' }
    });
    assert.equal(blockedIp.status, 403);

    const home = await call(base, 'GET', '/api/v1', { token });
    assert.equal(home.status, 200);
    assert.equal(home.json.project.name, 'Demo');
    assert.equal(home.json.project.benchmarks[0].id, 'aws/cis_test');
    assert.equal(home.json.scopes.includes('write'), true);

    const findings = await call(base, 'GET', '/api/v1/findings?touched=true', { token });
    assert.equal(findings.status, 200);
    assert.equal(findings.json.findings.length, 1);
    const prowler = findings.json.findings[0];
    assert.equal(prowler.review.status, 'false-positive');
    assert.equal(prowler.review.reason, 'The account is a lab.');
    assert.equal(prowler.review.note, 'Mention the lab in the report.');
    assert.equal(prowler.review.touched, true);
    assert.equal(prowler.scanner.fail, 1);
    assert.equal(prowler.controls[0].requirementId, '1.20');
    assert.equal(prowler.controls[0].validated, false);
    assert.equal(JSON.stringify(findings.json).includes('Other client'), false);

    const detail = await call(base, 'GET', `/api/v1/findings/${encodeURIComponent(prowler.id)}`, { token });
    assert.equal(detail.json.assets[0].name, 'analyzer');
    assert.match(detail.json.details || detail.json.observations.join('\n'), /not enabled/);

    const controls = await call(base, 'GET', '/api/v1/controls?validated=false', { token });
    assert.equal(controls.json.benchmarks[0].controls[0].scannerStatus, 'fail');
    assert.equal(controls.json.benchmarks[0].controls[0].findings[0].touched, true);

    const readOnly = await call(base, 'POST', '/api/access', {
      cookie,
      body: { name: 'look', projectId, expiresAt, write: false, ipAllowlist: [] }
    });
    assert.equal(readOnly.status, 201);
    const look = readOnly.json.token;
    const denied = await call(base, 'POST', '/api/v1/findings', {
      token: look,
      body: {
        title: 'Should not land',
        assets: [{ name: 'snap-1', status: 'FAIL' }]
      }
    });
    assert.equal(denied.status, 403);

    const custom = await call(base, 'POST', '/api/v1/findings', {
      token,
      body: {
        title: 'Public snapshot left behind',
        severity: 'high',
        status: 'confirmed',
        note: 'Created while reviewing storage.',
        details: 'A snapshot is shared outside the account.',
        impact: 'The data can be copied.',
        remediation: 'Make the snapshot private and rotate exposed data.',
        controls: [{ benchmarkId: 'aws/cis_test', requirementId: '1.20' }],
        assets: [{ name: 'snap-abc', region: 'us-east-1', status: 'FAIL', service: 'ec2' }]
      }
    });
    assert.equal(custom.status, 201, custom.text);
    assert.equal(custom.json.source, 'custom');
    assert.equal(custom.json.review.touched, true);
    assert.equal(custom.json.controls[0].validated, false);

    const content = await call(base, 'PATCH', `/api/v1/findings/${encodeURIComponent(prowler.id)}`, {
      token,
      body: { title: 'renamed' }
    });
    assert.equal(content.status, 400);

    const reviewed = await call(base, 'PATCH', '/api/v1/controls', {
      token,
      body: { benchmarkId: 'aws/cis_test', requirementId: '1.20', status: 'fail', note: 'Checked the console.' }
    });
    assert.equal(reviewed.status, 200, reviewed.text);
    assert.equal(reviewed.json.review.validated, true);
    assert.equal(reviewed.json.review.status, 'fail');

    const after = await call(base, 'GET', `/api/v1/findings/${encodeURIComponent(prowler.id)}`, { token });
    assert.equal(after.json.controls[0].validated, true);
    assert.equal(after.json.controls[0].reviewStatus, 'fail');

    const linked = await call(base, 'GET', '/api/v1/controls?benchmark=aws/cis_test', { token });
    const sources = linked.json.benchmarks[0].controls[0].findings.map(item => item.source);
    assert.deepEqual(sources.sort(), ['custom', 'prowler']);

    const removed = await call(base, 'DELETE', `/api/v1/findings/${encodeURIComponent(prowler.id)}`, { token });
    assert.equal(removed.status, 400);
    const removedCustom = await call(base, 'DELETE', `/api/v1/findings/${encodeURIComponent(custom.json.id)}`, { token });
    assert.equal(removedCustom.status, 200);
    const gone = await call(base, 'GET', `/api/v1/findings/${encodeURIComponent(custom.json.id)}`, { token });
    assert.equal(gone.status, 404);

    await new Promise(resolve => setTimeout(resolve, 100));
    const keys = JSON.parse(fs.readFileSync(path.join(tmp, 'api', 'keys.json'), 'utf8'));
    keys.keys[0].expiresAt = '2020-01-01T00:00:00.000Z';
    fs.writeFileSync(path.join(tmp, 'api', 'keys.json'), JSON.stringify(keys));
    const expired = await call(base, 'GET', '/api/v1', { token });
    assert.equal(expired.status, 401);

    const audit = fs.readFileSync(path.join(tmp, 'api', 'audit.log'), 'utf8');
    assert.equal(audit.includes(token), false);
    assert.equal(audit.includes(look), false);
    assert.match(audit, /control_reviewed/);
    assert.equal(audit.includes('Checked the console'), false);
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
