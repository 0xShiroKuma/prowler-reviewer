'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const dataRoot = path.join(__dirname, '..', 'data');
fs.mkdirSync(dataRoot, { recursive: true });
const tmp = fs.mkdtempSync(path.join(dataRoot, 'auth-test-'));
process.env.DATA_DIR = tmp;
process.env.COMPLIANCE_DIR = path.join(tmp, 'compliance');
process.env.CHECK_METADATA_DIR = path.join(tmp, 'meta');
delete process.env.COOKIE_SECURE;

const { app, auth } = require('./server');
const { pruneAttempts, pushAttempt } = require('./auth');

const USER = 'reviewer';
const PASS = 'correct-horse-battery';
const NEXT = 'correct-horse-battery-two';
const RESET = 'correct-horse-battery-three';
const BAD = 'not-the-right-passphrase';

function cookieHeader(setCookie) {
  const line = (setCookie || []).find(value => value.startsWith('pr_session='));
  if (!line) return '';
  return line.split(';')[0];
}

function tokenOf(cookie) {
  return cookie.split('=')[1] || '';
}

async function call(base, method, urlPath, { body, cookie, csrf = true, headers = {} } = {}) {
  const reqHeaders = { ...headers };
  if (csrf && method !== 'GET' && method !== 'HEAD') reqHeaders['X-Requested-With'] = 'prowler-reviewer';
  if (body !== undefined) reqHeaders['Content-Type'] = 'application/json';
  if (cookie) reqHeaders.Cookie = cookie;
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

test('lockout window does not slide when the cap is reached', () => {
  const windowMs = 1000;
  let list = [];
  list = pushAttempt(pruneAttempts(list, 0, windowMs), 0, 2);
  list = pushAttempt(pruneAttempts(list, 10, windowMs), 10, 2);
  const blocked = pruneAttempts(list, 20, windowMs);
  assert.equal(blocked.length, 2);
  assert.deepEqual(pushAttempt(blocked, 20, 2), blocked);
  assert.deepEqual(pruneAttempts(blocked, 2000, windowMs), []);
  assert.deepEqual(pruneAttempts([Date.now() + 60000], Date.now(), windowMs), []);
});

test('authentication', { timeout: 180000 }, async () => {
  const help = spawnSync(process.execPath, ['reset-password.js', '--help'], { cwd: __dirname, encoding: 'utf8' });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /password-stdin/);

  const argv = spawnSync(process.execPath, ['reset-password.js', '--password', 'secret'], {
    cwd: __dirname,
    encoding: 'utf8'
  });
  assert.notEqual(argv.status, 0);
  assert.match(argv.stderr, /command line/);

  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  try {
    const status = await call(base, 'GET', '/api/auth/status');
    assert.equal(status.json.setupRequired, true);

    const hidden = await call(base, 'GET', '/api/projects');
    assert.equal(hidden.status, 401);

    const tooBig = await call(base, 'POST', '/api/auth/login', {
      body: { username: USER, password: 'x'.repeat(9000) }
    });
    assert.equal(tooBig.status, 413);

    const noCsrf = await call(base, 'POST', '/api/auth/register', {
      csrf: false,
      body: { username: USER, password: PASS }
    });
    assert.equal(noCsrf.status, 403);

    const short = await call(base, 'POST', '/api/auth/register', { body: { username: USER, password: 'short-pass' } });
    assert.equal(short.status, 400);
    assert.match(short.json.error, /12 characters/);

    const common = await call(base, 'POST', '/api/auth/register', { body: { username: USER, password: 'password12345' } });
    assert.equal(common.status, 400);

    const containsUser = await call(base, 'POST', '/api/auth/register', {
      body: { username: USER, password: 'reviewer-passphrase' }
    });
    assert.equal(containsUser.status, 400);

    const created = await call(base, 'POST', '/api/auth/register', { body: { username: USER, password: PASS } });
    assert.equal(created.status, 201);
    assert.equal(created.json.username, USER);
    assert.equal(created.text.includes(PASS), false);
    const cookie = cookieHeader(created.setCookie);
    const token = tokenOf(cookie);
    assert.match(created.setCookie[0], /HttpOnly/);
    assert.match(created.setCookie[0], /SameSite=Strict/);
    assert.doesNotMatch(created.setCookie[0], /Secure/);
    assert.equal(token.length, 43);

    const account = fs.readFileSync(path.join(tmp, 'auth', 'account.json'), 'utf8');
    const sessions = fs.readFileSync(path.join(tmp, 'auth', 'sessions.json'), 'utf8');
    assert.equal(account.includes(PASS), false);
    assert.equal(sessions.includes(token), false);
    assert.equal(fs.statSync(path.join(tmp, 'auth', 'account.json')).mode & 0o077, 0);
    assert.equal(fs.statSync(path.join(tmp, 'auth', 'sessions.json')).mode & 0o077, 0);
    assert.equal(fs.statSync(path.join(tmp, 'auth')).mode & 0o077, 0);

    const projects = await call(base, 'GET', '/api/projects', { cookie });
    assert.equal(projects.status, 200);
    assert.deepEqual(projects.json, []);

    const blockedWrite = await call(base, 'POST', '/api/project/missing/state', { cookie, csrf: false, body: { statuses: {} } });
    assert.equal(blockedWrite.status, 403);
    const missingProject = await call(base, 'POST', '/api/project/missing/state', { cookie, body: { statuses: {} } });
    assert.equal(missingProject.status, 404);

    const again = await call(base, 'POST', '/api/auth/register', { body: { username: 'other', password: NEXT } });
    assert.equal(again.status, 403);
    assert.equal((await call(base, 'GET', '/api/auth/status')).json.setupRequired, false);

    const me = await call(base, 'GET', '/api/auth/me', { cookie });
    assert.equal(me.json.username, USER);

    const unknown = await call(base, 'POST', '/api/auth/login', { body: { username: 'nobody-else', password: BAD } });
    const wrong = await call(base, 'POST', '/api/auth/login', { body: { username: USER, password: BAD } });
    assert.equal(unknown.status, 401);
    assert.equal(wrong.status, 401);
    assert.equal(unknown.json.error, wrong.json.error);
    assert.equal(unknown.json.error, 'Invalid username or password.');

    await call(base, 'POST', '/api/auth/logout', { cookie });
    assert.equal((await call(base, 'GET', '/api/auth/me', { cookie })).status, 401);

    const loggedIn = await call(base, 'POST', '/api/auth/login', { body: { username: 'Reviewer', password: PASS } });
    assert.equal(loggedIn.status, 200);
    const session = cookieHeader(loggedIn.setCookie);

    const badChange = await call(base, 'POST', '/api/auth/password', {
      cookie: session,
      body: { currentPassword: BAD, newPassword: NEXT }
    });
    assert.equal(badChange.status, 400);

    const changed = await call(base, 'POST', '/api/auth/password', {
      cookie: session,
      body: { currentPassword: PASS, newPassword: NEXT }
    });
    assert.equal(changed.status, 200);
    assert.equal((await call(base, 'GET', '/api/projects', { cookie: session })).status, 401);

    const relogin = await call(base, 'POST', '/api/auth/login', { body: { username: USER, password: NEXT } });
    assert.equal(relogin.status, 200);
    const second = cookieHeader(relogin.setCookie);
    assert.equal((await call(base, 'GET', '/api/auth/me', { cookie: second })).status, 200);

    const cli = spawnSync(process.execPath, ['reset-password.js', '--password-stdin'], {
      cwd: __dirname,
      encoding: 'utf8',
      input: RESET + '\n',
      env: { DATA_DIR: tmp }
    });
    assert.equal(cli.status, 0, cli.stderr);
    assert.match(cli.stdout, /Password updated for reviewer/);
    assert.equal((cli.stdout + cli.stderr).includes(RESET), false);
    assert.equal((await call(base, 'GET', '/api/auth/me', { cookie: second })).status, 401);

    const afterReset = await call(base, 'POST', '/api/auth/login', { body: { username: USER, password: RESET } });
    assert.equal(afterReset.status, 200);
    assert.equal((await call(base, 'POST', '/api/auth/login', { body: { username: USER, password: NEXT } })).status, 401);

    for (let i = 0; i < 4; i += 1) {
      const attempt = await call(base, 'POST', '/api/auth/login', { body: { username: USER, password: BAD } });
      assert.equal(attempt.status, 401);
    }
    const locked = await call(base, 'POST', '/api/auth/login', { body: { username: USER, password: RESET } });
    assert.equal(locked.status, 429);
    assert.match(locked.json.error, /Too many attempts/);

    const audit = fs.readFileSync(path.join(tmp, 'auth', 'audit.log'), 'utf8');
    for (const secret of [PASS, NEXT, RESET, BAD]) assert.equal(audit.includes(secret), false);
    assert.match(audit, /password_reset/);
    assert.equal(typeof auth.store.hasAccount, 'function');
    assert.equal(auth.store.hasAccount(), true);
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
