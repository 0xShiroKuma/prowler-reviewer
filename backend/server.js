const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const DATA_DIR = process.env.DATA_DIR || '/data';
const COMPLIANCE_DIR = process.env.COMPLIANCE_DIR || '/compliance';
const CHECK_METADATA_DIR = process.env.CHECK_METADATA_DIR || '/check-metadata';
const MAX_HISTORY = 50;

app.use(cors());
app.use(express.json({ limit: '500mb' }));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

function projectDir(id) { return path.join(DATA_DIR, 'projects', id); }
function historyDir(id) { return path.join(projectDir(id), 'history'); }

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

// ─── Project endpoints ────────────────────────────────────────────────────────

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

  fs.writeFileSync(path.join(pDir, 'raw.json'), rawData, 'utf8');

  const name = req.body.name || req.file?.originalname || id;
  let preferred = [];
  try { preferred = JSON.parse(req.body.preferredBenchmarks || '[]'); } catch {}

  const state = {
    name,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    findingCount: 0,
    statuses: {},
    preferredBenchmarks: Array.isArray(preferred) ? preferred : []
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

app.get('/api/project/:id/state', (req, res) => {
  const fp = path.join(projectDir(req.params.id), 'state.json');
  const state = readJSON(fp, { statuses: {} });
  res.json(state);
});

app.post('/api/project/:id/state', (req, res) => {
  const id = req.params.id;
  const pDir = projectDir(id);
  if (!fs.existsSync(pDir)) return res.status(404).json({ error: 'Project not found' });

  const existing = readJSON(path.join(pDir, 'state.json'), { statuses: {} });
  const updated = { ...existing, ...req.body, updatedAt: new Date().toISOString() };
  writeJSON(path.join(pDir, 'state.json'), updated);
  saveSnapshot(id, updated);

  res.json({ ok: true });
});

app.get('/api/project/:id/history', (req, res) => {
  const hDir = historyDir(req.params.id);
  ensureDir(hDir);
  const files = fs.readdirSync(hDir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .reverse()
    .map(f => ({ filename: f, timestamp: f.replace('.json', '').replace(/-/g, (m, o) => o > 10 ? ':' : '-') }));
  res.json(files);
});

app.get('/api/project/:id/history/:filename', (req, res) => {
  const fp = path.join(historyDir(req.params.id), req.params.filename);
  const data = readJSON(fp);
  if (!data) return res.status(404).json({ error: 'Snapshot not found' });
  res.json(data);
});

app.post('/api/project/:id/history/:filename/restore', (req, res) => {
  const id = req.params.id;
  const fp = path.join(historyDir(id), req.params.filename);
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

// ─── Compliance catalog endpoints ─────────────────────────────────────────────

// List all available benchmarks with metadata (no full requirements payload)
app.get('/api/compliance/benchmarks', (req, res) => {
  const ids = walkComplianceDir(COMPLIANCE_DIR, '');
  const benchmarks = [];
  for (const id of ids) {
    const data = readJSON(path.join(COMPLIANCE_DIR, id + '.json'), null);
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
  res.setHeader('Content-Type', 'application/json');
  fs.createReadStream(fp).pipe(res);
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

app.listen(PORT, () => console.log(`Prowler Reviewer backend running on :${PORT}`));
