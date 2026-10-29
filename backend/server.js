const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { createAuth } = require('./auth');
const { createAgent } = require('./agent');
const { withStateLock, sanitizeCustomFindings, sanitizeControlReviews, sanitizeFindingEdits } = require('./review');

const app = express();
const PORT = process.env.PORT || 3001;
const DATA_DIR = process.env.DATA_DIR || '/data';
const COMPLIANCE_DIR = process.env.COMPLIANCE_DIR || '/compliance';
const CHECK_METADATA_DIR = process.env.CHECK_METADATA_DIR || '/check-metadata';
const MAX_HISTORY = 50;

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

const auth = createAuth({ dataDir: DATA_DIR });
app.use('/api/auth', express.json({ limit: '8kb', strict: true }));
app.use('/api/auth', auth.router);

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

function safeProjectId(id) {
  return typeof id === 'string' && /^proj_[A-Za-z0-9_-]+$/.test(id);
}

function projectDir(id) {
  if (!safeProjectId(id)) {
    const err = new Error('Invalid project id');
    err.status = 400;
    throw err;
  }
  const root = path.resolve(DATA_DIR, 'projects');
  const dir = path.resolve(root, id);
  if (!dir.startsWith(root + path.sep)) {
    const err = new Error('Invalid project id');
    err.status = 400;
    throw err;
  }
  return dir;
}

function historyDir(id) { return path.join(projectDir(id), 'history'); }
function scansDir(id) { return path.join(projectDir(id), 'scans'); }

function safeScanId(id) {
  return typeof id === 'string' && /^scan_[A-Za-z0-9_-]+$/.test(id);
}

function safeHistoryFilename(name) {
  return typeof name === 'string' && /^\d{4}-\d{2}-\d{2}T[0-9-]+Z\.json$/.test(name);
}

function historyPath(projectId, filename) {
  if (!safeHistoryFilename(filename)) return null;
  const dir = path.resolve(historyDir(projectId));
  const fp = path.resolve(dir, filename);
  if (!fp.startsWith(dir + path.sep)) return null;
  return fp;
}

// A project that only has raw.json keeps working until a scan is added.
// The first add or retest copies that file into scans/ and records it.
function migrateLegacyScan(projectId, state) {
  if (Array.isArray(state.scans) && state.scans.length) return state;
  const rawPath = path.join(projectDir(projectId), 'raw.json');
  if (!fs.existsSync(rawPath)) {
    state.scans = [];
    return state;
  }
  const id = 'scan_legacy';
  ensureDir(scansDir(projectId));
  const dest = path.join(scansDir(projectId), `${id}.json`);
  if (!fs.existsSync(dest)) fs.copyFileSync(rawPath, dest);
  state.scans = [{
    id,
    label: state.name || 'raw.json',
    addedAt: state.createdAt || new Date().toISOString(),
    replaces: null
  }];
  return state;
}

function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }

function readJSON(fp, fallback = null) {
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return fallback; }
}

function writeJSON(fp, data) {
  fs.writeFileSync(fp, JSON.stringify(data, null, 2), 'utf8');
}

function pruneHistory(projectId) {
  const hDir = historyDir(projectId);
  ensureDir(hDir);
  const files = fs.readdirSync(hDir)
    .filter(f => f.endsWith('.json'))
    .sort();
  while (files.length >= MAX_HISTORY) {
    fs.unlinkSync(path.join(hDir, files.shift()));
  }
}

function saveSnapshot(projectId, state) {
  pruneHistory(projectId);
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  writeJSON(path.join(historyDir(projectId), `${ts}.json`), state);
}

function walkComplianceDir(dir, base) {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  try {
    for (const entry of fs.readdirSync(dir)) {
      const full = path.join(dir, entry);
      const rel  = base ? `${base}/${entry}` : entry;
      if (fs.statSync(full).isDirectory()) {
        results.push(...walkComplianceDir(full, rel));
      } else if (entry.endsWith('.json')) {
        results.push(rel.replace(/\.json$/, ''));
      }
    }
  } catch { /* ignore unreadable dirs */ }
  return results;
}

const PROVIDER_LABELS = {
  aws: 'AWS',
  azure: 'Azure',
  gcp: 'GCP',
  kubernetes: 'Kubernetes',
  m365: 'M365',
  oraclecloud: 'OracleCloud',
  alibabacloud: 'AlibabaCloud',
  googleworkspace: 'GoogleWorkspace',
  github: 'GitHub',
  nhn: 'NHN',
};

function normalizeProvider(raw, benchmarkId) {
  const key = String(raw || '').trim().toLowerCase();
  const fromPath = (benchmarkId.split('/')[0] || '').toLowerCase();
  const lookup = key || fromPath;
  if (PROVIDER_LABELS[lookup]) return PROVIDER_LABELS[lookup];
  if (raw) return raw;
  if (fromPath) return fromPath.charAt(0).toUpperCase() + fromPath.slice(1);
  return 'Other';
}

function flattenChecks(checks) {
  if (Array.isArray(checks)) return checks.map(check => String(check));
  if (!checks || typeof checks !== 'object') return [];
  const out = [];
  for (const value of Object.values(checks)) {
    if (Array.isArray(value)) out.push(...value.map(check => String(check)));
    else if (value) out.push(String(value));
  }
  return [...new Set(out)];
}

function normalizeAttributes(attributes) {
  if (Array.isArray(attributes)) return attributes;
  if (attributes && typeof attributes === 'object') return [attributes];
  return [];
}

// Prowler now publishes two benchmark shapes. The UI reads the original
// Requirements / Checks / Attributes form, so newer files are translated here.
function normalizeBenchmark(data, benchmarkId) {
  if (!data || typeof data !== 'object') return null;
  if (Array.isArray(data.Requirements)) return data;
  if (!Array.isArray(data.requirements)) return null;
  const provider = data.Provider || data.provider || (String(benchmarkId).includes('/') ? '' : 'Multi-cloud');
  return {
    Framework: data.framework || '',
    Name: data.name || benchmarkId,
    Version: data.version || '',
    Provider: provider,
    Description: data.description || '',
    Requirements: data.requirements.map(req => ({
      Id: req.id || '',
      Description: req.description || req.name || '',
      Checks: flattenChecks(req.checks),
      Attributes: normalizeAttributes(req.attributes)
    }))
  };
}

function walkMetadataFiles(dir) {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  try {
    for (const entry of fs.readdirSync(dir)) {
      const full = path.join(dir, entry);
      if (fs.statSync(full).isDirectory()) {
        results.push(...walkMetadataFiles(full));
      } else if (entry.endsWith('.metadata.json')) {
        results.push(full);
      }
    }
  } catch { /* ignore unreadable dirs */ }
  return results;
}

let checkMetadataIndex = null;

function buildCheckMetadataIndex() {
  if (checkMetadataIndex) return checkMetadataIndex;
  const index = {};
  for (const fp of walkMetadataFiles(CHECK_METADATA_DIR)) {
    const data = readJSON(fp, null);
    if (!data?.CheckID) continue;
    const checkId = String(data.CheckID).toLowerCase();
    index[checkId] = data;
    const stem = path.basename(fp).replace(/\.metadata\.json$/i, '').toLowerCase();
    if (stem !== checkId) index[stem] = data;
  }
  checkMetadataIndex = index;
  return index;
}

function loadBenchmark(id) {
  if (!id || !/^[a-zA-Z0-9_./-]+$/.test(id) || id.includes('..')) return null;
  const base = path.resolve(COMPLIANCE_DIR);
  const fp = path.resolve(COMPLIANCE_DIR, id + '.json');
  if (!fp.startsWith(base + path.sep) && fp !== base) return null;
  if (!fs.existsSync(fp)) return null;
  return normalizeBenchmark(readJSON(fp, null), id);
}

const agentApi = createAgent({
  dataDir: DATA_DIR,
  projectDir,
  readJSON,
  writeJSON,
  saveSnapshot,
  loadBenchmark,
  metadataIndex: buildCheckMetadataIndex
});

// The harness API authenticates with its own key. It must be mounted before
// the session gate so a browser cookie cannot call it, and a key cannot ride
// the session middleware.
app.use('/api/v1', agentApi.router);
app.use('/api', auth.requireAuth);
app.use('/api/access', agentApi.access);
app.use(express.json({ limit: '500mb', strict: true }));

// ─── Project endpoints ────────────────────────────────────────────────────────

app.use('/api/project/:id', (req, res, next) => {
  if (!safeProjectId(req.params.id)) return res.status(400).json({ error: 'Invalid project id' });
  next();
});

app.get('/api/projects', (req, res) => {
  const base = path.join(DATA_DIR, 'projects');
  ensureDir(base);
  const projects = fs.readdirSync(base)
    .filter(f => {
      try { return fs.statSync(path.join(base, f)).isDirectory(); } catch { return false; }
    })
    .map(id => {
      const meta = readJSON(path.join(base, id, 'state.json'), {});
      return {
        id,
        name: meta.name || id,
        createdAt: meta.createdAt || null,
        updatedAt: meta.updatedAt || null,
        findingCount: meta.findingCount || 0
      };
    })
    .sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
  res.json(projects);
});

app.post('/api/project', upload.single('file'), (req, res) => {
  const id = `proj_${Date.now()}`;
  const pDir = projectDir(id);
  ensureDir(pDir);
  ensureDir(historyDir(id));

  const rawData = req.file ? req.file.buffer.toString('utf8') : req.body.rawJson;
  if (!rawData) return res.status(400).json({ error: 'No file provided' });

  const scanId = `scan_${Date.now()}`;
  ensureDir(scansDir(id));
  fs.writeFileSync(path.join(scansDir(id), `${scanId}.json`), rawData, 'utf8');

  const name = req.body.name || req.file?.originalname || id;
  let preferred = [];
  try { preferred = JSON.parse(req.body.preferredBenchmarks || '[]'); } catch {}

  const now = new Date().toISOString();
  const state = {
    name,
    createdAt: now,
    updatedAt: now,
    findingCount: 0,
    statuses: {},
    preferredBenchmarks: Array.isArray(preferred) ? preferred : [],
    scans: [{
      id: scanId,
      label: req.file?.originalname || 'scan.json',
      addedAt: now,
      replaces: null
    }]
  };
  writeJSON(path.join(pDir, 'state.json'), state);
  saveSnapshot(id, state);

  res.json({ id, name });
});

app.get('/api/project/:id/raw', (req, res) => {
  const fp = path.join(projectDir(req.params.id), 'raw.json');
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Not found' });
  res.setHeader('Content-Type', 'application/json');
  fs.createReadStream(fp).pipe(res);
});

app.get('/api/project/:id/scans/:scanId', (req, res) => {
  if (!safeScanId(req.params.scanId)) return res.status(400).json({ error: 'Invalid scan id' });
  const fp = path.join(scansDir(req.params.id), `${req.params.scanId}.json`);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Not found' });
  res.setHeader('Content-Type', 'application/json');
  fs.createReadStream(fp).pipe(res);
});

app.post('/api/project/:id/scans', upload.single('file'), (req, res) => {
  const projectId = req.params.id;
  const pDir = projectDir(projectId);
  if (!fs.existsSync(pDir)) return res.status(404).json({ error: 'Project not found' });
  if (!req.file) return res.status(400).json({ error: 'No file provided' });

  const statePath = path.join(pDir, 'state.json');
  const state = readJSON(statePath, {});
  migrateLegacyScan(projectId, state);

  let replaces = req.body.replaces || null;
  if (replaces === 'legacy') replaces = 'scan_legacy';
  if (replaces) {
    if (!safeScanId(replaces) || !state.scans.some(scan => scan.id === replaces)) {
      return res.status(400).json({ error: 'Scan to replace was not found' });
    }
  }

  const scanId = `scan_${Date.now()}`;
  ensureDir(scansDir(projectId));
  fs.writeFileSync(path.join(scansDir(projectId), `${scanId}.json`), req.file.buffer);

  const record = {
    id: scanId,
    label: req.file.originalname || `${scanId}.json`,
    addedAt: new Date().toISOString(),
    replaces
  };
  state.scans.push(record);
  state.updatedAt = new Date().toISOString();
  writeJSON(statePath, state);
  saveSnapshot(projectId, state);
  res.json({ scan: record, scans: state.scans });
});

app.delete('/api/project/:id/scans/:scanId', (req, res) => {
  const projectId = req.params.id;
  const scanId = req.params.scanId;
  if (!safeScanId(scanId)) return res.status(400).json({ error: 'Invalid scan id' });
  const pDir = projectDir(projectId);
  if (!fs.existsSync(pDir)) return res.status(404).json({ error: 'Project not found' });

  const statePath = path.join(pDir, 'state.json');
  const state = readJSON(statePath, {});
  const scans = Array.isArray(state.scans) ? state.scans : [];
  if (!scans.some(scan => scan.id === scanId)) return res.status(404).json({ error: 'Scan not found' });

  const fp = path.join(scansDir(projectId), `${scanId}.json`);
  if (fs.existsSync(fp)) fs.unlinkSync(fp);
  state.scans = scans.filter(scan => scan.id !== scanId);
  state.updatedAt = new Date().toISOString();
  writeJSON(statePath, state);
  saveSnapshot(projectId, state);
  res.json({ ok: true, scans: state.scans });
});

app.get('/api/project/:id/state', (req, res) => {
  const fp = path.join(projectDir(req.params.id), 'state.json');
  const state = readJSON(fp, { statuses: {} });
  res.json(state);
});

app.post('/api/project/:id/state', (req, res) => {
  const id = req.params.id;
  withStateLock(id, () => {
    const pDir = projectDir(id);
    if (!fs.existsSync(pDir)) return res.status(404).json({ error: 'Project not found' });

    const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
    if (Object.prototype.hasOwnProperty.call(body, 'customFindings') && !Array.isArray(body.customFindings)) {
      return res.status(400).json({ error: 'Invalid findings.' });
    }
    if (Object.prototype.hasOwnProperty.call(body, 'controlReviews') && (!body.controlReviews || typeof body.controlReviews !== 'object' || Array.isArray(body.controlReviews))) {
      return res.status(400).json({ error: 'Invalid control reviews.' });
    }
    if (Object.prototype.hasOwnProperty.call(body, 'findingEdits') && (!body.findingEdits || typeof body.findingEdits !== 'object' || Array.isArray(body.findingEdits))) {
      return res.status(400).json({ error: 'Invalid finding edits.' });
    }

    const existing = readJSON(path.join(pDir, 'state.json'), { statuses: {} });
    const updated = { ...existing, ...body, updatedAt: new Date().toISOString() };
    if (Object.prototype.hasOwnProperty.call(body, 'customFindings')) {
      updated.customFindings = sanitizeCustomFindings(body.customFindings);
    }
    if (Object.prototype.hasOwnProperty.call(body, 'controlReviews')) {
      updated.controlReviews = sanitizeControlReviews(body.controlReviews);
    }
    if (Object.prototype.hasOwnProperty.call(body, 'findingEdits')) {
      updated.findingEdits = sanitizeFindingEdits(body.findingEdits);
    }
    writeJSON(path.join(pDir, 'state.json'), updated);
    if (body._snapshot !== false) saveSnapshot(id, updated);

    res.json({ ok: true });
  }).catch(err => {
    console.error(err && err.stack ? err.stack.split('\n').slice(0, 4).join('\n') : 'state save failed');
    if (!res.headersSent) res.status(500).json({ error: 'Internal error.' });
  });
});

app.get('/api/project/:id/history', (req, res) => {
  const hDir = historyDir(req.params.id);
  ensureDir(hDir);
  const files = fs.readdirSync(hDir)
    .filter(safeHistoryFilename)
    .sort()
    .reverse()
    .map(f => ({ filename: f, timestamp: f.replace('.json', '').replace(/-/g, (m, o) => o > 10 ? ':' : '-') }));
  res.json(files);
});

app.get('/api/project/:id/history/:filename', (req, res) => {
  const fp = historyPath(req.params.id, req.params.filename);
  if (!fp) return res.status(400).json({ error: 'Invalid snapshot' });
  const data = readJSON(fp);
  if (!data) return res.status(404).json({ error: 'Snapshot not found' });
  res.json(data);
});

app.post('/api/project/:id/history/:filename/restore', (req, res) => {
  const id = req.params.id;
  const fp = historyPath(id, req.params.filename);
  if (!fp) return res.status(400).json({ error: 'Invalid snapshot' });
  const snapshot = readJSON(fp);
  if (!snapshot) return res.status(404).json({ error: 'Snapshot not found' });

  const current = readJSON(path.join(projectDir(id), 'state.json'), {});
  saveSnapshot(id, current);

  const restored = { ...snapshot, updatedAt: new Date().toISOString() };
  writeJSON(path.join(projectDir(id), 'state.json'), restored);

  res.json({ ok: true, state: restored });
});

app.delete('/api/project/:id', (req, res) => {
  const pDir = projectDir(req.params.id);
  if (!fs.existsSync(pDir)) return res.status(404).json({ error: 'Not found' });
  fs.rmSync(pDir, { recursive: true, force: true });
  res.json({ ok: true });
});

// ─── Catalog stamp (written at image build from the Prowler git ref) ─────────

app.get('/api/catalog', (req, res) => {
  res.json(readJSON('/prowler-catalog.json', {
    repo: null,
    ref: null,
    commit: null,
    complianceFiles: null,
    metadataFiles: null
  }));
});

// ─── Compliance catalog endpoints ─────────────────────────────────────────────

// List all available benchmarks with metadata (no full requirements payload)
app.get('/api/compliance/benchmarks', (req, res) => {
  const ids = walkComplianceDir(COMPLIANCE_DIR, '');
  const benchmarks = [];
  for (const id of ids) {
    const data = normalizeBenchmark(readJSON(path.join(COMPLIANCE_DIR, id + '.json'), null), id);
    if (!data || !Array.isArray(data.Requirements)) continue;
    const profiles = new Set();
    const types = new Set();
    for (const r of data.Requirements) {
      for (const a of (r.Attributes || [])) {
        if (a.Profile) profiles.add(a.Profile);
        if (a.Type) types.add(a.Type);
      }
    }
    benchmarks.push({
      id,
      framework: data.Framework || '',
      name: data.Name || id,
      version: data.Version || '',
      provider: normalizeProvider(data.Provider, id),
      profiles: [...profiles].sort(),
      types: [...types].sort(),
      requirementsCount: data.Requirements.length
    });
  }
  benchmarks.sort((a, b) => a.provider.localeCompare(b.provider) || a.name.localeCompare(b.name));
  res.json(benchmarks);
});

// Return full benchmark JSON for a given id (e.g. azure/cis_5.0_azure)
app.get('/api/compliance/benchmark/*', (req, res) => {
  const id = req.params[0];
  if (!id || !/^[a-zA-Z0-9_./-]+$/.test(id) || id.includes('..')) {
    return res.status(400).json({ error: 'Invalid benchmark ID' });
  }
  const base = path.resolve(COMPLIANCE_DIR);
  const fp   = path.resolve(COMPLIANCE_DIR, id + '.json');
  if (!fp.startsWith(base + path.sep) && fp !== base) {
    return res.status(400).json({ error: 'Access denied' });
  }
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Not found' });
  const data = normalizeBenchmark(readJSON(fp, null), id);
  if (!data) return res.status(404).json({ error: 'Not found' });
  res.json(data);
});

// ─── Prowler check metadata endpoints ─────────────────────────────────────────

app.get('/api/check-metadata', (req, res) => {
  res.json(buildCheckMetadataIndex());
});

app.get('/api/check-metadata/:checkId', (req, res) => {
  const id = String(req.params.checkId || '').toLowerCase();
  if (!id || !/^[a-z0-9_-]+$/.test(id)) {
    return res.status(400).json({ error: 'Invalid check ID' });
  }
  const data = buildCheckMetadataIndex()[id];
  if (!data) return res.status(404).json({ error: 'Not found' });
  res.json(data);
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status = Number(err.status || err.statusCode || 0);
  if (status === 413 || err.type === 'entity.too.large' || err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'Request too large.' });
  }
  if (status === 400) return res.status(400).json({ error: 'Invalid request.' });
  console.error(err && err.stack ? err.stack.split('\n').slice(0, 4).join('\n') : 'request error');
  return res.status(500).json({ error: 'Internal error.' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    const catalog = readJSON('/prowler-catalog.json', null);
    const source = catalog?.commit
      ? `catalog ${catalog.ref}@${String(catalog.commit).slice(0, 12)} (${catalog.complianceFiles} compliance files, ${catalog.metadataFiles} checks)`
      : 'no catalog stamp';
    console.log(`Prowler Reviewer backend running on :${PORT} — ${source}`);
  });
}

module.exports = { app, auth };
