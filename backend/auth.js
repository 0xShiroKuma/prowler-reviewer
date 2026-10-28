'use strict';

// Single local account. Passwords are scrypt (OWASP parameters). The cookie
// holds a random token; only its SHA-256 is stored. Lockout state is on disk
// so a container password reset can clear it.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');

const COOKIE_NAME = 'pr_session';
const CSRF_HEADER = 'x-requested-with';
const CSRF_VALUE = 'prowler-reviewer';

const SCRYPT_N = 131072;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEYLEN = 32;
const SALT_LEN = 16;
const SCRYPT_MAXMEM = 256 * 1024 * 1024;

const MIN_PASSWORD = 5;
const MAX_PASSWORD = 128;
const MIN_USERNAME = 3;
const MAX_USERNAME = 64;
const USERNAME_RE = /^[A-Za-z0-9._@+-]+$/;

const IDLE_MS = 12 * 60 * 60 * 1000;
const ABSOLUTE_MS = 7 * 24 * 60 * 60 * 1000;
const TOUCH_MS = 5 * 60 * 1000;
const MAX_SESSIONS = 5;
const LOCK_WINDOW_MS = 15 * 60 * 1000;
const AUTH_BODY_LIMIT = 8192;

const LIMITS = {
  login: { max: 5, windowMs: LOCK_WINDOW_MS },
  register: { max: 10, windowMs: LOCK_WINDOW_MS },
  password: { max: 5, windowMs: LOCK_WINDOW_MS }
};

const INVALID_CREDENTIALS = 'Invalid username or password.';

let dummyRecord = null;

function pruneAttempts(list, now, windowMs) {
  return (Array.isArray(list) ? list : []).filter(t =>
    Number.isFinite(t) && t <= now + 5000 && now - t < windowMs
  );
}

function pushAttempt(list, now, max) {
  if (list.length >= max) return list.slice();
  return list.concat(now);
}

function secureCookieEnabled() {
  const value = String(process.env.COOKIE_SECURE || '').toLowerCase();
  return value === '1' || value === 'true';
}

function cookieHeader(token, { clear = false } = {}) {
  const parts = [
    `${COOKIE_NAME}=${clear ? '' : token}`,
    'HttpOnly',
    'SameSite=Strict',
    'Path=/',
    `Max-Age=${clear ? 0 : Math.floor(ABSOLUTE_MS / 1000)}`
  ];
  if (secureCookieEnabled()) parts.push('Secure');
  return parts.join('; ');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(SALT_LEN);
  const hash = crypto.scryptSync(password, salt, KEYLEN, {
    N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: SCRYPT_MAXMEM
  });
  return {
    algorithm: 'scrypt',
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    salt: salt.toString('base64'),
    hash: hash.toString('base64')
  };
}

function getDummyRecord() {
  if (!dummyRecord) dummyRecord = hashPassword(crypto.randomBytes(32).toString('hex'));
  return dummyRecord;
}

function decodeB64(value, length) {
  if (typeof value !== 'string' || !value) return null;
  let buf;
  try { buf = Buffer.from(value, 'base64'); } catch { return null; }
  if (buf.length !== length) return null;
  return buf;
}

function isValidRecord(record) {
  if (!record || record.algorithm !== 'scrypt') return false;
  if (record.N !== SCRYPT_N || record.r !== SCRYPT_R || record.p !== SCRYPT_P) return false;
  return Boolean(decodeB64(record.salt, SALT_LEN) && decodeB64(record.hash, KEYLEN));
}

function scryptOf(password, record) {
  return crypto.scryptSync(password, Buffer.from(record.salt, 'base64'), KEYLEN, {
    N: record.N, r: record.r, p: record.p, maxmem: SCRYPT_MAXMEM
  });
}

function checkPassword(password, record) {
  const valid = isValidRecord(record);
  const usable = typeof password === 'string' && password.length > 0 && password.length <= MAX_PASSWORD;
  const target = valid && usable ? record : getDummyRecord();
  const material = usable ? password : 'invalid-password-attempt';
  let actual;
  try {
    actual = scryptOf(material, target);
  } catch {
    actual = Buffer.alloc(KEYLEN);
  }
  const expected = decodeB64(target.hash, KEYLEN) || Buffer.alloc(KEYLEN);
  const match = actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  return Boolean(match && valid && usable && target === record);
}

function namesEqual(stored, given) {
  const left = Buffer.from(String(stored || '').toLowerCase(), 'utf8');
  const right = Buffer.from(String(given || '').trim().toLowerCase(), 'utf8');
  if (left.length !== right.length) {
    crypto.timingSafeEqual(left, left);
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

function validateUsername(username) {
  if (typeof username !== 'string') return 'Username must be 3 to 64 characters.';
  const name = username.trim();
  if (name.length < MIN_USERNAME || name.length > MAX_USERNAME) {
    return 'Username must be 3 to 64 characters.';
  }
  if (!USERNAME_RE.test(name)) {
    return 'Username can use letters, numbers, and . _ @ + - only.';
  }
  return '';
}

function validatePassword(password) {
  if (typeof password !== 'string' || !password) return 'Password is required.';
  if (password.length < MIN_PASSWORD) return `Password must be at least ${MIN_PASSWORD} characters.`;
  if (password.length > MAX_PASSWORD) return `Password must be at most ${MAX_PASSWORD} characters.`;
  return '';
}

function lockMessage(retryAfterSec) {
  const minutes = Math.max(1, Math.ceil(retryAfterSec / 60));
  return `Too many attempts. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`;
}

function openAuthStore(dataDir) {
  const authDir = path.join(dataDir, 'auth');
  const accountPath = path.join(authDir, 'account.json');
  const sessionPath = path.join(authDir, 'sessions.json');
  const lockoutPath = path.join(authDir, 'lockout.json');
  const auditPath = path.join(authDir, 'audit.log');

  function ensureDir() {
    fs.mkdirSync(authDir, { recursive: true });
    fs.chmodSync(authDir, 0o700);
  }

  function writePrivate(fp, text) {
    ensureDir();
    const tmp = `${fp}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(tmp, text, { mode: 0o600 });
    fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, fp);
    fs.chmodSync(fp, 0o600);
  }

  function hasAccount() {
    try { return fs.statSync(accountPath).isFile(); } catch { return false; }
  }

  function readAccount() {
    try {
      const data = JSON.parse(fs.readFileSync(accountPath, 'utf8'));
      if (!data || typeof data.username !== 'string' || !isValidRecord(data.password)) return null;
      return data;
    } catch {
      return null;
    }
  }

  function writeAccount(account) {
    writePrivate(accountPath, JSON.stringify(account));
  }

  function createAccount(account) {
    ensureDir();
    let fd;
    try {
      fd = fs.openSync(accountPath, 'wx', 0o600);
    } catch (err) {
      if (err.code === 'EEXIST') return false;
      throw err;
    }
    try {
      fs.writeSync(fd, JSON.stringify(account));
    } finally {
      fs.closeSync(fd);
    }
    fs.chmodSync(accountPath, 0o600);
    return true;
  }

  function readSessions() {
    try {
      const data = JSON.parse(fs.readFileSync(sessionPath, 'utf8'));
      if (!data || !Array.isArray(data.sessions)) return [];
      return data.sessions.filter(session =>
        session &&
        typeof session.id === 'string' &&
        typeof session.username === 'string' &&
        Number.isFinite(session.createdAt) &&
        Number.isFinite(session.lastSeen)
      );
    } catch {
      return [];
    }
  }

  function writeSessions(sessions) {
    writePrivate(sessionPath, JSON.stringify({ sessions }));
  }

  function liveSessions(sessions, now) {
    return sessions.filter(session =>
      now - session.createdAt < ABSOLUTE_MS &&
      now - session.lastSeen < IDLE_MS &&
      now + 5000 >= session.createdAt
    );
  }

  function sha256(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
  }

  function validToken(token) {
    return typeof token === 'string' && /^[A-Za-z0-9_-]{43}$/.test(token);
  }

  function createSession(username) {
    const now = Date.now();
    const token = crypto.randomBytes(32).toString('base64url');
    const sessions = liveSessions(readSessions(), now);
    sessions.push({ id: sha256(token), username, createdAt: now, lastSeen: now });
    sessions.sort((a, b) => a.lastSeen - b.lastSeen);
    while (sessions.length > MAX_SESSIONS) sessions.shift();
    writeSessions(sessions);
    return token;
  }

  function clearSessions() {
    writeSessions([]);
  }

  function sessionFromToken(token) {
    if (!validToken(token)) return null;
    const now = Date.now();
    const presented = Buffer.from(sha256(token), 'hex');
    const all = readSessions();
    const live = liveSessions(all, now);
    let found = null;
    for (const session of live) {
      let idBuf;
      try { idBuf = Buffer.from(session.id, 'hex'); } catch { continue; }
      if (idBuf.length !== presented.length) continue;
      if (crypto.timingSafeEqual(idBuf, presented)) found = session;
    }
    if (!found) {
      if (live.length !== all.length) writeSessions(live);
      return null;
    }
    if (now - found.lastSeen >= TOUCH_MS || live.length !== all.length) {
      found.lastSeen = now;
      writeSessions(live);
    }
    return { username: found.username };
  }

  function dropSession(token) {
    if (!validToken(token)) return;
    const id = sha256(token);
    writeSessions(readSessions().filter(session => session.id !== id));
  }

  function readLockout() {
    try {
      const data = JSON.parse(fs.readFileSync(lockoutPath, 'utf8'));
      return {
        login: Array.isArray(data.login) ? data.login : [],
        register: Array.isArray(data.register) ? data.register : [],
        password: Array.isArray(data.password) ? data.password : []
      };
    } catch {
      return { login: [], register: [], password: [] };
    }
  }

  function writeLockout(state) {
    writePrivate(lockoutPath, JSON.stringify(state));
  }

  function gate(bucket) {
    const now = Date.now();
    const rule = LIMITS[bucket];
    const state = readLockout();
    const recent = pruneAttempts(state[bucket], now, rule.windowMs);
    if (recent.length !== (state[bucket] || []).length) {
      state[bucket] = recent;
      writeLockout(state);
    }
    if (recent.length >= rule.max) {
      const retryAfter = Math.max(1, Math.ceil((recent[0] + rule.windowMs - now) / 1000));
      return { blocked: true, retryAfter };
    }
    return { blocked: false, retryAfter: 0 };
  }

  function recordAttempt(bucket) {
    const now = Date.now();
    const rule = LIMITS[bucket];
    const state = readLockout();
    const recent = pruneAttempts(state[bucket], now, rule.windowMs);
    state[bucket] = pushAttempt(recent, now, rule.max);
    writeLockout(state);
  }

  function clearFailures(buckets) {
    const state = readLockout();
    for (const bucket of buckets) state[bucket] = [];
    writeLockout(state);
  }

  function audit(event, fields = {}) {
    try {
      ensureDir();
      const safe = { t: new Date().toISOString(), event };
      for (const [key, value] of Object.entries(fields)) {
        if (key === 'password' || key === 'currentPassword' || key === 'newPassword') continue;
        if (typeof value === 'string') safe[key] = value.replace(/[\r\n]/g, ' ').slice(0, 200);
        else if (typeof value === 'number' || typeof value === 'boolean') safe[key] = value;
      }
      fs.appendFileSync(auditPath, JSON.stringify(safe) + '\n', { mode: 0o600 });
      fs.chmodSync(auditPath, 0o600);
      if (fs.statSync(auditPath).size > 1024 * 1024) {
        fs.renameSync(auditPath, auditPath + '.1');
      }
    } catch {
      console.error('audit log failed');
    }
  }

  function blocked(result, ip, bucket) {
    audit('lockout', { ip, bucket });
    return {
      ok: false,
      status: 429,
      error: lockMessage(result.retryAfter),
      retryAfter: result.retryAfter
    };
  }

  function register({ username, password, ip }) {
    if (hasAccount()) {
      return { ok: false, status: 403, error: 'An account already exists. Sign in instead.' };
    }
    const gateResult = gate('register');
    if (gateResult.blocked) return blocked(gateResult, ip, 'register');
    recordAttempt('register');

    const name = typeof username === 'string' ? username.trim() : '';
    const userProblem = validateUsername(name);
    if (userProblem) return { ok: false, status: 400, error: userProblem };
    const passProblem = validatePassword(password, name);
    if (passProblem) return { ok: false, status: 400, error: passProblem };

    const now = new Date().toISOString();
    const created = createAccount({
      username: name,
      password: hashPassword(password),
      createdAt: now,
      passwordChangedAt: now
    });
    if (!created) {
      return { ok: false, status: 403, error: 'An account already exists. Sign in instead.' };
    }
    const token = createSession(name);
    audit('register', { username: name, ip });
    return { ok: true, status: 201, username: name, token };
  }

  function login({ username, password, ip }) {
    const gateResult = gate('login');
    if (gateResult.blocked) return blocked(gateResult, ip, 'login');

    const givenUser = typeof username === 'string' ? username : '';
    const givenPass = typeof password === 'string' ? password : '';
    const account = readAccount();
    const passOk = checkPassword(givenPass, account && account.password);
    const userOk = account ? namesEqual(account.username, givenUser) : false;
    if (!account || !passOk || !userOk) {
      recordAttempt('login');
      audit('login_failure', { ip });
      return { ok: false, status: 401, error: INVALID_CREDENTIALS };
    }
    clearFailures(['login']);
    const token = createSession(account.username);
    audit('login_success', { username: account.username, ip });
    return { ok: true, status: 200, username: account.username, token };
  }

  function changePassword({ currentPassword, newPassword, ip }) {
    const account = readAccount();
    if (!account) return { ok: false, status: 401, error: 'Authentication required.' };
    const gateResult = gate('password');
    if (gateResult.blocked) return blocked(gateResult, ip, 'password');

    const current = typeof currentPassword === 'string' ? currentPassword : '';
    const next = typeof newPassword === 'string' ? newPassword : '';
    if (!checkPassword(current, account.password)) {
      recordAttempt('password');
      audit('password_change_failure', { username: account.username, ip });
      return { ok: false, status: 400, error: 'Current password is incorrect.' };
    }
    if (current === next) {
      return { ok: false, status: 400, error: 'New password must be different from the current password.' };
    }
    const problem = validatePassword(next, account.username);
    if (problem) return { ok: false, status: 400, error: problem };

    writeAccount({
      username: account.username,
      password: hashPassword(next),
      createdAt: account.createdAt || new Date().toISOString(),
      passwordChangedAt: new Date().toISOString()
    });
    clearSessions();
    clearFailures(['login', 'password']);
    audit('password_change', { username: account.username, ip });
    return { ok: true, status: 200 };
  }

  function resetPassword(newPassword, { username, ip } = {}) {
    const existing = readAccount();
    const exists = hasAccount();
    let name = existing ? existing.username : '';
    if (!existing) {
      if (!username) {
        return {
          ok: false,
          status: 400,
          code: exists ? 'corrupt' : 'no-account',
          error: exists
            ? 'The account file is unreadable. Rerun with --username to set the account again.'
            : 'No account exists yet. Rerun with --username to create one.'
        };
      }
      const problem = validateUsername(username);
      if (problem) return { ok: false, status: 400, error: problem };
      name = username.trim();
    }
    const passProblem = validatePassword(newPassword, name);
    if (passProblem) return { ok: false, status: 400, error: passProblem };

    const now = new Date().toISOString();
    writeAccount({
      username: name,
      password: hashPassword(newPassword),
      createdAt: existing?.createdAt || now,
      passwordChangedAt: now
    });
    clearSessions();
    clearFailures(['login', 'password']);
    audit(existing ? 'password_reset' : 'register', { username: name, ip: ip || 'container', via: 'container' });
    return { ok: true, status: 200, username: name, created: !existing };
  }

  getDummyRecord();

  return {
    hasAccount,
    register,
    login,
    changePassword,
    resetPassword,
    sessionFromToken,
    dropSession,
    audit
  };
}

function tokenFrom(req) {
  const header = req.headers.cookie;
  if (!header || typeof header !== 'string' || header.length > 4096) return '';
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === COOKIE_NAME) return part.slice(idx + 1).trim();
  }
  return '';
}

function csrfOk(req) {
  return req.get(CSRF_HEADER) === CSRF_VALUE;
}

function jsonContent(req) {
  return String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json');
}

function clientIp(req) {
  const forwarded = req.get('x-real-ip');
  if (typeof forwarded === 'string' && /^[0-9a-fA-F:.]+$/.test(forwarded) && forwarded.length <= 64) {
    return forwarded;
  }
  const addr = req.socket && req.socket.remoteAddress;
  return typeof addr === 'string' ? addr.slice(0, 64) : '';
}

function sendResult(res, result) {
  if (result.retryAfter) res.set('Retry-After', String(result.retryAfter));
  if (result.token) res.setHeader('Set-Cookie', cookieHeader(result.token));
  if (result.ok) {
    const payload = result.username ? { username: result.username } : { ok: true };
    return res.status(result.status).json(payload);
  }
  return res.status(result.status).json({ error: result.error });
}

function createAuth({ dataDir }) {
  const store = openAuthStore(dataDir);
  const router = express.Router();

  router.use((req, res, next) => {
    const length = Number(req.headers['content-length'] || 0);
    if (Number.isFinite(length) && length > AUTH_BODY_LIMIT) {
      res.status(413).json({ error: 'Request too large.' });
      req.destroy();
      return;
    }
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && !csrfOk(req)) {
      return res.status(403).json({ error: 'Request blocked.' });
    }
    next();
  });

  router.get('/status', (req, res) => {
    res.json({ setupRequired: !store.hasAccount() });
  });

  router.get('/me', (req, res) => {
    const session = store.sessionFromToken(tokenFrom(req));
    if (!session) return res.status(401).json({ error: 'Authentication required.' });
    res.json({ username: session.username });
  });

  router.post('/register', (req, res) => {
    if (!jsonContent(req)) return res.status(415).json({ error: 'Expected JSON.' });
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'Invalid request.' });
    }
    sendResult(res, store.register({
      username: body.username,
      password: body.password,
      ip: clientIp(req)
    }));
  });

  router.post('/login', (req, res) => {
    if (!jsonContent(req)) return res.status(415).json({ error: 'Expected JSON.' });
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'Invalid request.' });
    }
    sendResult(res, store.login({
      username: body.username,
      password: body.password,
      ip: clientIp(req)
    }));
  });

  router.post('/logout', (req, res) => {
    store.dropSession(tokenFrom(req));
    store.audit('logout', { ip: clientIp(req) });
    res.setHeader('Set-Cookie', cookieHeader('', { clear: true }));
    res.json({ ok: true });
  });

  router.post('/password', (req, res) => {
    if (!jsonContent(req)) return res.status(415).json({ error: 'Expected JSON.' });
    const session = store.sessionFromToken(tokenFrom(req));
    if (!session) return res.status(401).json({ error: 'Authentication required.' });
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'Invalid request.' });
    }
    const result = store.changePassword({
      currentPassword: body.currentPassword,
      newPassword: body.newPassword,
      ip: clientIp(req)
    });
    if (result.ok) res.setHeader('Set-Cookie', cookieHeader('', { clear: true }));
    sendResult(res, result);
  });

  function requireAuth(req, res, next) {
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && !csrfOk(req)) {
      return res.status(403).json({ error: 'Request blocked.' });
    }
    const session = store.sessionFromToken(tokenFrom(req));
    if (!session) {
      res.setHeader('Set-Cookie', cookieHeader('', { clear: true }));
      return res.status(401).json({ error: 'Authentication required.' });
    }
    req.authUser = session.username;
    next();
  }

  return { router, requireAuth, store, AUTH_BODY_LIMIT };
}

module.exports = {
  createAuth,
  openAuthStore,
  pruneAttempts,
  pushAttempt,
  COOKIE_NAME,
  CSRF_VALUE,
  validatePassword,
  validateUsername,
  AUTH_BODY_LIMIT
};
