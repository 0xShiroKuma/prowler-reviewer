const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const DATA_DIR = process.env.DATA_DIR || '/data';
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

// List all projects
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

// Create project (upload JSON)
app.post('/api/project', upload.single('file'), (req, res) => {
  const id = `proj_${Date.now()}`;
  const pDir = projectDir(id);
  ensureDir(pDir);
  ensureDir(historyDir(id));

  const rawData = req.file ? req.file.buffer.toString('utf8') : req.body.rawJson;
  if (!rawData) return res.status(400).json({ error: 'No file provided' });

  fs.writeFileSync(path.join(pDir, 'raw.json'), rawData, 'utf8');

  const name = req.body.name || req.file?.originalname || id;
  const state = {
    name,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    findingCount: 0,
    statuses: {}
  };
  writeJSON(path.join(pDir, 'state.json'), state);
  saveSnapshot(id, state);

  res.json({ id, name });
});

// Get project raw JSON
app.get('/api/project/:id/raw', (req, res) => {
  const fp = path.join(projectDir(req.params.id), 'raw.json');
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Not found' });
  res.setHeader('Content-Type', 'application/json');
  fs.createReadStream(fp).pipe(res);
});

// Get project state
app.get('/api/project/:id/state', (req, res) => {
  const fp = path.join(projectDir(req.params.id), 'state.json');
  const state = readJSON(fp, { statuses: {} });
  res.json(state);
});

// Save project state (auto-save)
app.post('/api/project/:id/state', (req, res) => {
  const id = req.params.id;
  const pDir = projectDir(id);
  if (!fs.existsSync(pDir)) return res.status(404).json({ error: 'Project not found' });

  const existing = readJSON(path.join(pDir, 'state.json'), { statuses: {} });
  const updated = {
    ...existing,
    ...req.body,
    updatedAt: new Date().toISOString()
  };
  writeJSON(path.join(pDir, 'state.json'), updated);
  saveSnapshot(id, updated);

  res.json({ ok: true });
});

// Get history list
app.get('/api/project/:id/history', (req, res) => {
  const hDir = historyDir(req.params.id);
  ensureDir(hDir);
  const files = fs.readdirSync(hDir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .reverse()
    .map(f => ({ filename: f, timestamp: f.replace('.json', '').replace(/T/, 'T').replace(/-/g, (m, o) => o > 10 ? ':' : '-') }));
  res.json(files);
});

// Get specific history snapshot
app.get('/api/project/:id/history/:filename', (req, res) => {
  const fp = path.join(historyDir(req.params.id), req.params.filename);
  const data = readJSON(fp);
  if (!data) return res.status(404).json({ error: 'Snapshot not found' });
  res.json(data);
});

// Restore a snapshot
app.post('/api/project/:id/history/:filename/restore', (req, res) => {
  const id = req.params.id;
  const fp = path.join(historyDir(id), req.params.filename);
  const snapshot = readJSON(fp);
  if (!snapshot) return res.status(404).json({ error: 'Snapshot not found' });

  // Save current state as a snapshot before restoring
  const current = readJSON(path.join(projectDir(id), 'state.json'), {});
  saveSnapshot(id, current);

  const restored = { ...snapshot, updatedAt: new Date().toISOString() };
  writeJSON(path.join(projectDir(id), 'state.json'), restored);

  res.json({ ok: true, state: restored });
});

// Delete project
app.delete('/api/project/:id', (req, res) => {
  const pDir = projectDir(req.params.id);
  if (!fs.existsSync(pDir)) return res.status(404).json({ error: 'Not found' });
  fs.rmSync(pDir, { recursive: true, force: true });
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Prowler Reviewer backend running on :${PORT}`));
