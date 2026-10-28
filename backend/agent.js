'use strict';

// HTTP API for review harnesses. Browser sessions are not accepted here.
// A key is created in the UI, stored as a SHA-256, scoped to one project,
// and rejected when it is expired, revoked, or used from outside its address list.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const net = require('net');
const express = require('express');

const {
  FINDING_STATUSES,
  CONTROL_STATUSES,
  withStateLock,
  reviewKey,
  sanitizeCustomFindings,
  sanitizeControlReviews,
  sanitizeFindingEdits,
  buildFindingEdit,
  RICH_TEXT_MAX,
  sanitizeControlRef,
  buildProjectReview,
  publicFinding,
  publicControl,
  benchmarkSummary,
  buildCustomRecord,
  setMapValue,
  BENCHMARK_ID,
  readJson
} = require('./review');

const KEY_PREFIX = 'prk_';
const TOKEN_RE = /^prk_[A-Za-z0-9_-]{43}$/;
const MAX_KEYS = 20;
const MAX_ALLOW = 32;
const MAX_AGE_MS = 90 * 24 * 60 * 60 * 1000;
const READ_LIMIT = 120;
const READ_WINDOW_MS = 60 * 1000;
const WRITE_LIMIT = 30;
const WRITE_WINDOW_MS = 60 * 1000;
const FAIL_LIMIT = 30;
const FAIL_WINDOW_MS = 15 * 60 * 1000;
const TOUCH_MS = 5 * 60 * 1000;

const rateBuckets = new Map();
let keyChain = Promise.resolve();

function withKeyLock(fn) {
  const run = keyChain.then(fn, fn);
  keyChain = run.then(() => undefined, () => undefined);
  return run;
}

function hitLimit(bucket, max, windowMs) {
  const now = Date.now();
  let entry = rateBuckets.get(bucket);
  if (!entry || now - entry.start >= windowMs) {
    entry = { start: now, count: 0 };
    rateBuckets.set(bucket, entry);
  }
  entry.count += 1;
  if (entry.count > max) {
    return { blocked: true, retryAfter: Math.max(1, Math.ceil((entry.start + windowMs - now) / 1000)) };
  }
  return { blocked: false, retryAfter: 0 };
}

function clientIp(req) {
  const forwarded = req.get('x-real-ip');
  if (typeof forwarded === 'string' && net.isIP(forwarded) && forwarded.length <= 64) return normalizeIp(forwarded);
  const addr = req.socket && req.socket.remoteAddress;
  return typeof addr === 'string' ? normalizeIp(addr) : '';
}

function normalizeIp(value) {
  const text = String(value || '').trim().toLowerCase();
  if (text.startsWith('::ffff:')) {
    const v4 = text.slice(7);
    if (net.isIP(v4) === 4) return v4;
  }
  return text;
}

function parseAllow(entry) {
  const text = String(entry || '').trim().toLowerCase();
  if (!text || text.length > 80 || text.includes('%')) return null;
  const slash = text.lastIndexOf('/');
  const addr = slash === -1 ? text : text.slice(0, slash);
  const family = net.isIP(addr);
  if (!family) return null;
  const max = family === 4 ? 32 : 128;
  const bits = slash === -1 ? max : Number(text.slice(slash + 1));
  if (!Number.isInteger(bits) || bits < 0 || bits > max) return null;
  return { family, addr: normalizeIp(addr), bits };
}

function ipv4Parts(addr) {
  const parts = addr.split('.').map(part => Number(part));
  if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function ipv6Parts(addr) {
  const text = normalizeIp(addr);
  if (net.isIP(text) !== 6) return null;
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
  if (halves.length === 1 && head.length !== 8) return null;
  const missing = 8 - head.length - tail.length;
  if (missing < 0) return null;
  const groups = [...head, ...Array(missing).fill('0'), ...tail];
  if (groups.length !== 8) return null;
  const nums = groups.map(group => parseInt(group, 16));
  if (nums.some(num => !Number.isInteger(num) || num < 0 || num > 0xffff)) return null;
  return nums;
}

function ipAllowed(allowlist, ip) {
  if (!allowlist.length) return true;
  const family = net.isIP(ip);
  if (!family) return false;
  return allowlist.some(entry => {
    if (entry.family !== family) return false;
    if (family === 4) {
      const left = ipv4Parts(entry.addr);
      const right = ipv4Parts(ip);
      if (left == null || right == null) return false;
      if (entry.bits === 0) return true;
      const mask = entry.bits === 32 ? 0xffffffff : ((0xffffffff << (32 - entry.bits)) >>> 0);
      return (left & mask) === (right & mask);
    }
    const left = ipv6Parts(entry.addr);
    const right = ipv6Parts(ip);
    if (!left || !right) return false;
    let bits = entry.bits;
    for (let i = 0; i < 8 && bits > 0; i += 1) {
      const take = Math.min(16, bits);
      const mask = take === 16 ? 0xffff : ((0xffff << (16 - take)) & 0xffff);
      if ((left[i] & mask) !== (right[i] & mask)) return false;
      bits -= take;
    }
    return true;
  });
}

function isLocalhostEntry(entry) {
  if (!entry) return false;
  if (entry.family === 4 && entry.addr === '127.0.0.1' && entry.bits === 32) return true;
  return entry.family === 6 && entry.bits === 128 && (entry.addr === '::1' || entry.addr === '0:0:0:0:0:0:0:1');
}

// A published Docker port shows the host as the bridge gateway, not 127.0.0.1.
function gatewayFromRoute(text) {
  const lines = String(text || '').trim().split('\n').slice(1);
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts[1] !== '00000000' || !parts[2] || parts[2] === '00000000') continue;
    const value = Number.parseInt(parts[2], 16);
    if (!Number.isFinite(value)) continue;
    return `${value & 255}.${(value >> 8) & 255}.${(value >> 16) & 255}.${(value >> 24) & 255}`;
  }
  return '';
}

let cachedGateway;
function hostGateway() {
  if (cachedGateway !== undefined) return cachedGateway;
  try {
    cachedGateway = gatewayFromRoute(fs.readFileSync('/proc/net/route', 'utf8'));
  } catch {
    cachedGateway = '';
  }
  return cachedGateway;
}

function clientAllowed(allowlist, ip, aliases = []) {
  if (!allowlist.length) return true;
  if (ipAllowed(allowlist, ip)) return true;
  if (!allowlist.some(isLocalhostEntry)) return false;
  const normalized = normalizeIp(ip);
  if (normalized === '127.0.0.1' || normalized === '::1') return true;
  return aliases.includes(normalized);
}

function sanitizeAllowlist(value) {
  if (value == null || value === '') return [];
  const list = Array.isArray(value) ? value : String(value).split(/[\n,]/);
  const out = [];
  for (const item of list) {
    if (out.length >= MAX_ALLOW) break;
    const parsed = parseAllow(item);
    if (!parsed) {
      if (String(item || '').trim()) return { error: `Unrecognized address: ${String(item).trim().slice(0, 80)}` };
      continue;
    }
    const text = parsed.bits === (parsed.family === 4 ? 32 : 128) ? parsed.addr : `${parsed.addr}/${parsed.bits}`;
    if (!out.includes(text)) out.push(text);
  }
  return out;
}

function createAgent({
  dataDir,
  projectDir,
  readJSON,
  writeJSON,
  saveSnapshot,
  loadBenchmark,
  metadataIndex
}) {
  const apiDir = path.join(dataDir, 'api');
  const keyPath = path.join(apiDir, 'keys.json');
  const auditPath = path.join(apiDir, 'audit.log');
  const dummyHash = crypto.createHash('sha256').update('prowler-reviewer-dummy-key').digest();

  function ensureDir() {
    fs.mkdirSync(apiDir, { recursive: true });
    try { fs.chmodSync(apiDir, 0o700); } catch { /* volume may ignore chmod */ }
  }

  function writePrivate(fp, text) {
    ensureDir();
    const tmp = `${fp}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(tmp, text, { mode: 0o600 });
    try { fs.chmodSync(tmp, 0o600); } catch { /* ignore */ }
    fs.renameSync(tmp, fp);
    try { fs.chmodSync(fp, 0o600); } catch { /* ignore */ }
  }

  function readKeys() {
    const data = readJson(keyPath, { keys: [] });
    return Array.isArray(data?.keys) ? data.keys.filter(key => key && typeof key.id === 'string' && typeof key.hash === 'string') : [];
  }

  function writeKeys(keys) {
    writePrivate(keyPath, JSON.stringify({ keys }));
  }

  function audit(event, fields = {}) {
    try {
      ensureDir();
      const safe = { t: new Date().toISOString(), event };
      for (const [key, value] of Object.entries(fields)) {
        if (key === 'token' || key === 'password' || key === 'note' || key === 'reason' || key === 'details') continue;
        if (typeof value === 'string') safe[key] = value.replace(/[\r\n]/g, ' ').slice(0, 200);
        else if (typeof value === 'number' || typeof value === 'boolean') safe[key] = value;
      }
      fs.appendFileSync(auditPath, JSON.stringify(safe) + '\n', { mode: 0o600 });
      try { fs.chmodSync(auditPath, 0o600); } catch { /* ignore */ }
      if (fs.statSync(auditPath).size > 1024 * 1024) fs.renameSync(auditPath, auditPath + '.1');
    } catch {
      console.error('api audit log failed');
    }
  }

  function publicKey(key, projects) {
    const project = projects.find(item => item.id === key.projectId);
    const expires = Date.parse(key.expiresAt);
    return {
      id: key.id,
      name: key.name,
      projectId: key.projectId,
      projectName: project?.name || key.projectId,
      scopes: key.scopes,
      expiresAt: key.expiresAt,
      expired: !Number.isFinite(expires) || expires <= Date.now(),
      ipAllowlist: key.ipAllowlist || [],
      prefix: key.prefix,
      createdAt: key.createdAt,
      lastUsedAt: key.lastUsedAt || null
    };
  }

  function projectList() {
    const base = path.join(dataDir, 'projects');
    if (!fs.existsSync(base)) return [];
    return fs.readdirSync(base).filter(id => {
      try { return fs.statSync(path.join(base, id)).isDirectory(); } catch { return false; }
    }).map(id => {
      const state = readJSON(path.join(base, id, 'state.json'), {});
      return { id, name: state.name || id };
    });
  }

  const access = express.Router();
  access.use(express.json({ limit: '16kb', strict: true }));

  access.get('/', (req, res) => {
    const projects = projectList();
    const keys = readKeys()
      .map(key => publicKey(key, projects))
      .sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    res.json({ keys });
  });

  access.post('/', (req, res) => {
    withKeyLock(() => {
      const body = req.body;
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        res.status(400).json({ error: 'Invalid request.' });
        return;
      }
      const name = typeof body.name === 'string' ? body.name.trim() : '';
      if (name.length < 1 || name.length > 64 || /[\u0000-\u001F\u007F]/.test(name)) {
        res.status(400).json({ error: 'Name must be 1 to 64 characters.' });
        return;
      }
      const projectId = typeof body.projectId === 'string' ? body.projectId : '';
      if (!/^proj_[A-Za-z0-9_-]+$/.test(projectId) || !fs.existsSync(projectDir(projectId))) {
        res.status(400).json({ error: 'Choose a project for this key.' });
        return;
      }
      const expires = Date.parse(body.expiresAt);
      if (!Number.isFinite(expires)) {
        res.status(400).json({ error: 'Set an expiry date.' });
        return;
      }
      const delta = expires - Date.now();
      if (delta < 60 * 1000) {
        res.status(400).json({ error: 'Expiry must be in the future.' });
        return;
      }
      if (delta > MAX_AGE_MS + 36 * 60 * 60 * 1000) {
        res.status(400).json({ error: 'Expiry cannot be more than 90 days away.' });
        return;
      }
      const allow = sanitizeAllowlist(body.ipAllowlist);
      if (!Array.isArray(allow)) {
        res.status(400).json({ error: allow.error });
        return;
      }
      const keys = readKeys().filter(key => Date.parse(key.expiresAt) > Date.now());
      if (keys.length >= MAX_KEYS) {
        res.status(409).json({ error: 'Revoke an existing key before creating another. Twenty live keys is the maximum.' });
        return;
      }
      const scopes = ['read'];
      if (body.write === true) scopes.push('write');
      const secret = crypto.randomBytes(32).toString('base64url');
      const token = `${KEY_PREFIX}${secret}`;
      const record = {
        id: `key_${crypto.randomBytes(9).toString('base64url')}`,
        name,
        projectId,
        hash: crypto.createHash('sha256').update(token).digest('hex'),
        prefix: token.slice(0, 12),
        scopes,
        expiresAt: new Date(expires).toISOString(),
        ipAllowlist: allow,
        createdAt: new Date().toISOString(),
        lastUsedAt: null,
        createdBy: req.authUser || ''
      };
      writeKeys(readKeys().concat(record));
      audit('key_created', { keyId: record.id, projectId, ip: clientIp(req), write: scopes.includes('write'), addresses: allow.length });
      res.status(201).json({
        token,
        key: publicKey(record, projectList())
      });
    }).catch(err => {
      console.error(err && err.stack ? err.stack.split('\n').slice(0, 4).join('\n') : 'key create failed');
      if (!res.headersSent) res.status(500).json({ error: 'Internal error.' });
    });
  });

  access.delete('/:id', (req, res) => {
    withKeyLock(() => {
      const keys = readKeys();
      const key = keys.find(item => item.id === req.params.id);
      if (!key) {
        res.status(404).json({ error: 'Key not found.' });
        return;
      }
      writeKeys(keys.filter(item => item.id !== key.id));
      audit('key_revoked', { keyId: key.id, projectId: key.projectId, ip: clientIp(req) });
      res.json({ ok: true });
    }).catch(err => {
      console.error(err && err.message ? err.message : 'key revoke failed');
      if (!res.headersSent) res.status(500).json({ error: 'Internal error.' });
    });
  });

  function findKey(token) {
    const presented = crypto.createHash('sha256').update(typeof token === 'string' ? token : '').digest();
    let found = null;
    for (const key of readKeys()) {
      let buf;
      try { buf = Buffer.from(key.hash, 'hex'); } catch { continue; }
      if (buf.length !== presented.length) continue;
      if (crypto.timingSafeEqual(buf, presented)) found = key;
    }
    if (!found) crypto.timingSafeEqual(dummyHash, dummyHash);
    return found;
  }

  function bearer(req) {
    const header = req.get('authorization') || '';
    const match = header.match(/^Bearer ([A-Za-z0-9_-]+)$/);
    return match ? match[1] : '';
  }

  function deny(res, status, error, retryAfter) {
    if (retryAfter) res.set('Retry-After', String(retryAfter));
    res.status(status).json({ error });
  }

  function authenticate(req, res, next) {
    const token = bearer(req);
    const ip = clientIp(req);
    if (!TOKEN_RE.test(token)) {
      const limited = hitLimit(`fail:${ip}`, FAIL_LIMIT, FAIL_WINDOW_MS);
      if (limited.blocked) return deny(res, 429, 'Too many attempts. Try again later.', limited.retryAfter);
      audit('agent_denied', { ip, reason: 'invalid' });
      return deny(res, 401, 'Invalid API key.');
    }
    const key = findKey(token);
    if (!key) {
      const limited = hitLimit(`fail:${ip}`, FAIL_LIMIT, FAIL_WINDOW_MS);
      if (limited.blocked) return deny(res, 429, 'Too many attempts. Try again later.', limited.retryAfter);
      audit('agent_denied', { ip, reason: 'invalid' });
      return deny(res, 401, 'Invalid API key.');
    }
    if (!(Date.parse(key.expiresAt) > Date.now())) {
      audit('agent_denied', { ip, keyId: key.id, reason: 'expired' });
      return deny(res, 401, 'This key has expired.');
    }
    const allow = (key.ipAllowlist || []).map(parseAllow).filter(Boolean);
    const gateway = hostGateway();
    if (key.ipAllowlist?.length && !clientAllowed(allow, ip, gateway ? [gateway] : [])) {
      audit('agent_denied', { ip, keyId: key.id, reason: 'address' });
      return deny(res, 403, 'This address is not allowed for this key.');
    }
    const writing = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
    const limited = hitLimit(`use:${key.id}:${writing ? 'w' : 'r'}`, writing ? WRITE_LIMIT : READ_LIMIT, writing ? WRITE_WINDOW_MS : READ_WINDOW_MS);
    if (limited.blocked) return deny(res, 429, 'Too many requests. Try again later.', limited.retryAfter);
    req.agentKey = key;
    req.agentIp = ip;
    const last = Date.parse(key.lastUsedAt || 0);
    if (!Number.isFinite(last) || Date.now() - last >= TOUCH_MS) {
      withKeyLock(() => {
        const keys = readKeys();
        const current = keys.find(item => item.id === key.id);
        if (!current) return;
        current.lastUsedAt = new Date().toISOString();
        writeKeys(keys);
      }).catch(() => {});
    }
    next();
  }

  function requireWrite(req, res, next) {
    if (!req.agentKey.scopes?.includes('write')) {
      audit('agent_denied', { ip: req.agentIp, keyId: req.agentKey.id, reason: 'scope' });
      return deny(res, 403, 'This key cannot change data.');
    }
    next();
  }

  function loadReview(projectId, extraBenchmarks = []) {
    const dir = projectDir(projectId);
    if (!fs.existsSync(dir)) return null;
    const state = readJSON(path.join(dir, 'state.json'), {});
    const preferred = Array.isArray(state.preferredBenchmarks) ? state.preferredBenchmarks : [];
    const wanted = [...new Set([...preferred, ...extraBenchmarks].filter(id => typeof id === 'string' && BENCHMARK_ID.test(id) && !id.includes('..')))];
    const benchmarks = [];
    for (const id of wanted) {
      const data = loadBenchmark(id);
      if (!data) continue;
      benchmarks.push({
        id,
        name: data.Name || id,
        data,
        selected: preferred.includes(id)
      });
    }
    const review = buildProjectReview({
      projectPath: dir,
      state,
      metadataIndex: metadataIndex(),
      benchmarks
    });
    return { dir, preferred, benchmarks, ...review, stored: state };
  }

  function controlsFor(loaded, benchmarkId) {
    const benchmark = loaded.benchmarks.find(item => item.id === benchmarkId);
    if (!benchmark) return null;
    return {
      benchmark: { ...benchmarkSummary(benchmark), selected: benchmark.selected },
      controls: (benchmark.data.Requirements || []).map(requirement =>
        publicControl(benchmark, requirement, loaded.findings, loaded.state)
      )
    };
  }

  function page(list, req) {
    const offset = Math.max(0, Number.parseInt(req.query.offset, 10) || 0);
    const limit = Math.min(200, Math.max(1, Number.parseInt(req.query.limit, 10) || 100));
    return {
      total: list.length,
      offset,
      limit,
      nextOffset: offset + limit < list.length ? offset + limit : null
    };
  }

  function filterFindings(findings, query) {
    return findings.filter(finding => {
      if (query.source && finding.source !== query.source) return false;
      if (query.status && (finding.review.status || '') !== query.status) return false;
      if (query.touched === 'true' && !finding.review.touched) return false;
      if (query.touched === 'false' && finding.review.touched) return false;
      if (query.scanner === 'fail' && !(finding.scanner.fail > 0)) return false;
      if (query.scanner === 'pass' && !(finding.scanner.pass > 0)) return false;
      if (query.scanner === 'manual' && !(finding.scanner.manual > 0)) return false;
      if (query.q) {
        const hay = `${finding.title} ${finding.id} ${finding.service}`.toLowerCase();
        if (!hay.includes(String(query.q).toLowerCase().slice(0, 200))) return false;
      }
      return true;
    });
  }

  function saveState(projectId, dir, stored, next, snapshot) {
    const updated = {
      ...stored,
      ...next,
      customFindings: sanitizeCustomFindings(next.customFindings),
      controlReviews: sanitizeControlReviews(next.controlReviews),
      findingEdits: sanitizeFindingEdits(Object.prototype.hasOwnProperty.call(next, 'findingEdits') ? next.findingEdits : stored.findingEdits),
      updatedAt: new Date().toISOString()
    };
    delete updated._agent;
    writeJSON(path.join(dir, 'state.json'), updated);
    if (snapshot) saveSnapshot(projectId, updated);
    return updated;
  }

  function referencedBenchmarks(record) {
    return (record?.controls || []).map(control => control.benchmarkId);
  }

  function controlsExist(record) {
    for (const control of record.controls || []) {
      const clean = sanitizeControlRef(control);
      if (!clean) return `Unknown control ${control.benchmarkId || ''}:${control.requirementId || ''}.`;
      const data = loadBenchmark(clean.benchmarkId);
      if (!data) return `Benchmark not found: ${clean.benchmarkId}.`;
      const ok = (data.Requirements || []).some(requirement => requirement.Id === clean.requirementId);
      if (!ok) return `Control ${clean.requirementId} is not in ${clean.benchmarkId}.`;
    }
    return '';
  }

  const router = express.Router();
  router.use((req, res, next) => {
    const length = Number(req.headers['content-length'] || 0);
    if (Number.isFinite(length) && length > 3 * 1024 * 1024) {
      res.status(413).json({ error: 'Request too large.' });
      return;
    }
    next();
  });
  router.use(express.json({ limit: '3mb', strict: true }));
  router.use(authenticate);

  router.get('/', (req, res) => {
    const loaded = loadReview(req.agentKey.projectId);
    if (!loaded) return deny(res, 404, 'Project not found.');
    const state = loaded.stored;
    res.json({
      project: {
        id: req.agentKey.projectId,
        name: state.name || req.agentKey.projectId,
        updatedAt: state.updatedAt || null,
        benchmarks: loaded.benchmarks.filter(item => item.selected).map(benchmarkSummary)
      },
      scopes: req.agentKey.scopes,
      expiresAt: req.agentKey.expiresAt,
      key: { id: req.agentKey.id, name: req.agentKey.name, prefix: req.agentKey.prefix },
      review: {
        touched: 'A finding is touched when it has a pentester status, false-positive reason, or note, or when it was created in this tool.',
        validated: 'A benchmark control is validated when the pentester has set its review status in Compliance.'
      }
    });
  });

  router.get('/findings', (req, res) => {
    const loaded = loadReview(req.agentKey.projectId);
    if (!loaded) return deny(res, 404, 'Project not found.');
    const views = loaded.findings.map(finding => publicFinding(finding, loaded.state, loaded.benchmarks, loaded.findings));
    const filtered = filterFindings(views, req.query);
    const window = page(filtered, req);
    res.json({
      ...window,
      findings: filtered.slice(window.offset, window.offset + window.limit)
    });
  });

  router.get('/findings/:id', (req, res) => {
    const loaded = loadReview(req.agentKey.projectId);
    if (!loaded) return deny(res, 404, 'Project not found.');
    const finding = loaded.findings.find(item => item.id === req.params.id);
    if (!finding) return deny(res, 404, 'Finding not found.');
    res.json(publicFinding(finding, loaded.state, loaded.benchmarks, loaded.findings, { includeAssets: true }));
  });

  router.get('/benchmarks', (req, res) => {
    const loaded = loadReview(req.agentKey.projectId);
    if (!loaded) return deny(res, 404, 'Project not found.');
    res.json({
      benchmarks: loaded.benchmarks.filter(item => item.selected).map(benchmark => ({
        ...benchmarkSummary(benchmark),
        requirements: (benchmark.data.Requirements || []).length
      }))
    });
  });

  router.get('/controls', (req, res) => {
    const benchmarkId = typeof req.query.benchmark === 'string' ? req.query.benchmark : '';
    const loaded = loadReview(req.agentKey.projectId, benchmarkId ? [benchmarkId] : []);
    if (!loaded) return deny(res, 404, 'Project not found.');
    const ids = benchmarkId
      ? [benchmarkId]
      : loaded.benchmarks.filter(item => item.selected).map(item => item.id);
    if (benchmarkId && !loaded.benchmarks.some(item => item.id === benchmarkId)) {
      return deny(res, 404, 'Benchmark not found.');
    }
    const groups = ids.map(id => controlsFor(loaded, id)).filter(Boolean);
    const validated = req.query.validated;
    if (validated === 'true' || validated === 'false') {
      const want = validated === 'true';
      for (const group of groups) group.controls = group.controls.filter(control => control.review.validated === want);
    }
    res.json({ benchmarks: groups });
  });

  function jsonBody(req, res) {
    if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) {
      res.status(415).json({ error: 'Expected JSON.' });
      return null;
    }
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      res.status(400).json({ error: 'Invalid request.' });
      return null;
    }
    return body;
  }

  router.post('/findings', requireWrite, (req, res) => {
    const body = jsonBody(req, res);
    if (!body) return;
    const projectId = req.agentKey.projectId;
    withStateLock(projectId, () => {
      const loaded = loadReview(projectId);
      if (!loaded) return deny(res, 404, 'Project not found.');
      const built = buildCustomRecord(body);
      if (built.error) return deny(res, 400, built.error);
      const missing = controlsExist(built.finding);
      if (missing) return deny(res, 400, missing);
      const status = typeof body.status === 'string' ? body.status : '';
      const reason = typeof body.reason === 'string' ? body.reason.replace(/\u0000/g, '').slice(0, 16000) : '';
      const note = typeof body.note === 'string' ? body.note.replace(/\u0000/g, '').slice(0, RICH_TEXT_MAX) : '';
      if (!FINDING_STATUSES.has(status)) return deny(res, 400, 'Unknown finding status.');
      const customFindings = loaded.state.customFindings.concat(built.finding);
      const next = {
        ...loaded.state,
        customFindings,
        statuses: setMapValue(loaded.state.statuses, built.finding.id, status),
        reasons: setMapValue(loaded.state.reasons, built.finding.id, reason),
        notes: setMapValue(loaded.state.notes, built.finding.id, note)
      };
      saveState(projectId, loaded.dir, loaded.stored, next, true);
      audit('finding_created', { keyId: req.agentKey.id, projectId, ip: req.agentIp, findingId: built.finding.id });
      const again = loadReview(projectId, referencedBenchmarks(built.finding));
      const finding = again.findings.find(item => item.id === built.finding.id);
      res.status(201).json(publicFinding(finding, again.state, again.benchmarks, again.findings, { includeAssets: true }));
    }).catch(err => {
      console.error(err && err.stack ? err.stack.split('\n').slice(0, 4).join('\n') : 'finding create failed');
      if (!res.headersSent) res.status(500).json({ error: 'Internal error.' });
    });
  });

  router.patch('/findings/:id', requireWrite, (req, res) => {
    const body = jsonBody(req, res);
    if (!body) return;
    const projectId = req.agentKey.projectId;
    const findingId = req.params.id;
    withStateLock(projectId, () => {
      const loaded = loadReview(projectId);
      if (!loaded) return deny(res, 404, 'Project not found.');
      const finding = loaded.findings.find(item => item.id === findingId);
      if (!finding) return deny(res, 404, 'Finding not found.');
      const status = Object.prototype.hasOwnProperty.call(body, 'status') ? body.status : (loaded.state.statuses[findingId] || '');
      const reason = Object.prototype.hasOwnProperty.call(body, 'reason') ? body.reason : (loaded.state.reasons[findingId] || '');
      const note = Object.prototype.hasOwnProperty.call(body, 'note') ? body.note : (loaded.state.notes[findingId] || '');
      if (typeof status !== 'string' || !FINDING_STATUSES.has(status)) return deny(res, 400, 'Unknown finding status.');
      if (typeof reason !== 'string' || typeof note !== 'string') return deny(res, 400, 'Invalid request.');
      let customFindings = loaded.state.customFindings;
      let findingEdits = sanitizeFindingEdits(loaded.state.findingEdits);
      if (finding.source !== 'custom') {
        const contentKeys = ['title', 'severity', 'cloud', 'service', 'details', 'impact', 'remediation', 'observations', 'controls', 'assets'];
        if (contentKeys.some(key => Object.prototype.hasOwnProperty.call(body, key))) {
          const built = buildFindingEdit(body, findingEdits[findingId]);
          if (built.error) return deny(res, 400, built.error);
          if (built.edit?.controls) {
            const missing = controlsExist({ controls: built.edit.controls });
            if (missing) return deny(res, 400, missing);
          }
          if (built.edit) findingEdits[findingId] = built.edit;
          else delete findingEdits[findingId];
        }
      } else {
        const existing = customFindings.find(item => item.id === findingId);
        const built = buildCustomRecord(body, existing);
        if (built.error) return deny(res, 400, built.error);
        const missing = controlsExist(built.finding);
        if (missing) return deny(res, 400, missing);
        customFindings = customFindings.map(item => item.id === findingId ? built.finding : item);
      }
      const next = {
        ...loaded.state,
        customFindings,
        findingEdits,
        statuses: setMapValue(loaded.state.statuses, findingId, status),
        reasons: setMapValue(loaded.state.reasons, findingId, reason.replace(/\u0000/g, '').slice(0, 16000)),
        notes: setMapValue(loaded.state.notes, findingId, note.replace(/\u0000/g, '').slice(0, RICH_TEXT_MAX))
      };
      saveState(projectId, loaded.dir, loaded.stored, next, true);
      audit('finding_updated', { keyId: req.agentKey.id, projectId, ip: req.agentIp, findingId });
      const again = loadReview(projectId);
      const updated = again.findings.find(item => item.id === findingId);
      res.json(publicFinding(updated, again.state, again.benchmarks, again.findings, { includeAssets: true }));
    }).catch(err => {
      console.error(err && err.stack ? err.stack.split('\n').slice(0, 4).join('\n') : 'finding update failed');
      if (!res.headersSent) res.status(500).json({ error: 'Internal error.' });
    });
  });

  router.delete('/findings/:id', requireWrite, (req, res) => {
    const projectId = req.agentKey.projectId;
    const findingId = req.params.id;
    withStateLock(projectId, () => {
      const loaded = loadReview(projectId);
      if (!loaded) return deny(res, 404, 'Project not found.');
      const finding = loaded.findings.find(item => item.id === findingId);
      if (!finding) return deny(res, 404, 'Finding not found.');
      if (finding.source !== 'custom') return deny(res, 400, 'Prowler findings cannot be deleted.');
      const next = {
        ...loaded.state,
        customFindings: loaded.state.customFindings.filter(item => item.id !== findingId),
        statuses: setMapValue(loaded.state.statuses, findingId, ''),
        reasons: setMapValue(loaded.state.reasons, findingId, ''),
        notes: setMapValue(loaded.state.notes, findingId, '')
      };
      saveState(projectId, loaded.dir, loaded.stored, next, true);
      audit('finding_deleted', { keyId: req.agentKey.id, projectId, ip: req.agentIp, findingId });
      res.json({ ok: true });
    }).catch(err => {
      console.error(err && err.message ? err.message : 'finding delete failed');
      if (!res.headersSent) res.status(500).json({ error: 'Internal error.' });
    });
  });

  router.patch('/controls', requireWrite, (req, res) => {
    const body = jsonBody(req, res);
    if (!body) return;
    const benchmarkId = typeof body.benchmarkId === 'string' ? body.benchmarkId : '';
    const requirementId = typeof body.requirementId === 'string' ? body.requirementId : '';
    const clean = sanitizeControlRef({ benchmarkId, requirementId });
    if (!clean) return deny(res, 400, 'Unknown control.');
    if (Object.prototype.hasOwnProperty.call(body, 'status') && !CONTROL_STATUSES.has(body.status)) {
      return deny(res, 400, 'Unknown control status. Use pass, fail, manual, n/a, or an empty string.');
    }
    if (Object.prototype.hasOwnProperty.call(body, 'note') && typeof body.note !== 'string') {
      return deny(res, 400, 'Invalid request.');
    }
    const projectId = req.agentKey.projectId;
    withStateLock(projectId, () => {
      const data = loadBenchmark(clean.benchmarkId);
      if (!data || !(data.Requirements || []).some(requirement => requirement.Id === clean.requirementId)) {
        return deny(res, 404, 'Control not found.');
      }
      const loaded = loadReview(projectId, [clean.benchmarkId]);
      if (!loaded) return deny(res, 404, 'Project not found.');
      const key = reviewKey(clean.benchmarkId, clean.requirementId);
      const current = loaded.state.controlReviews[key] || { status: '', note: '', updatedAt: null };
      const status = Object.prototype.hasOwnProperty.call(body, 'status') ? body.status : current.status;
      const note = Object.prototype.hasOwnProperty.call(body, 'note') ? body.note.replace(/\u0000/g, '').slice(0, 8000) : current.note;
      const controlReviews = { ...loaded.state.controlReviews };
      if (!status && !note) delete controlReviews[key];
      else controlReviews[key] = { status, note, updatedAt: new Date().toISOString() };
      const next = { ...loaded.state, controlReviews };
      saveState(projectId, loaded.dir, loaded.stored, next, true);
      audit('control_reviewed', { keyId: req.agentKey.id, projectId, ip: req.agentIp, benchmarkId: clean.benchmarkId, requirementId: clean.requirementId });
      const again = loadReview(projectId, [clean.benchmarkId]);
      const group = controlsFor(again, clean.benchmarkId);
      const control = group.controls.find(item => item.id === clean.requirementId);
      res.json(control);
    }).catch(err => {
      console.error(err && err.message ? err.message : 'control update failed');
      if (!res.headersSent) res.status(500).json({ error: 'Internal error.' });
    });
  });

  router.use((req, res) => {
    res.status(404).json({ error: 'Not found.' });
  });

  return { router, access };
}

module.exports = {
  createAgent,
  parseAllow,
  ipAllowed,
  clientAllowed,
  gatewayFromRoute,
  normalizeIp
};
