'use strict';

// Shared review model for the browser save path and the agent API.
// Scanner results (PASS / FAIL / MANUAL) stay separate from the pentester's
// review status and from a manual judgement on a benchmark control.

const fs = require('fs');
const path = require('path');

const FINDING_STATUSES = new Set(['', 'confirmed', 'flagged', 'false-positive', 'reported']);
const CONTROL_STATUSES = new Set(['', 'pass', 'fail', 'manual', 'n/a']);
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'informational']);
const ASSET_STATUSES = new Set(['FAIL', 'PASS', 'MANUAL']);
const CUSTOM_ID = /^custom_[A-Za-z0-9_-]{16,64}$/;
const BENCHMARK_ID = /^[a-zA-Z0-9_./-]{1,180}$/;
const REQUIREMENT_ID = /^[A-Za-z0-9][A-Za-z0-9._()[\]:/+-]{0,159}$/;

const stateLocks = new Map();

function withStateLock(projectId, fn) {
  const prev = stateLocks.get(projectId) || Promise.resolve();
  const run = prev.then(fn, fn);
  const settled = run.then(() => undefined, () => undefined);
  stateLocks.set(projectId, settled);
  settled.then(() => {
    if (stateLocks.get(projectId) === settled) stateLocks.delete(projectId);
  });
  return run;
}

function clampText(value, max) {
  if (typeof value !== 'string') return '';
  return value.replace(/\u0000/g, '').slice(0, max);
}

function reviewKey(benchmarkId, requirementId) {
  return `${benchmarkId}::${requirementId}`;
}

function splitReviewKey(key) {
  if (typeof key !== 'string') return null;
  const sep = key.indexOf('::');
  if (sep <= 0) return null;
  const benchmarkId = key.slice(0, sep);
  const requirementId = key.slice(sep + 2);
  if (!BENCHMARK_ID.test(benchmarkId) || !REQUIREMENT_ID.test(requirementId) || requirementId.includes('::')) return null;
  if (benchmarkId.includes('..')) return null;
  return { benchmarkId, requirementId };
}

function sanitizeAsset(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const name = clampText(raw.name, 300).trim();
  if (!name) return null;
  const status = ASSET_STATUSES.has(raw.status) ? raw.status : 'FAIL';
  return {
    name,
    status,
    region: clampText(raw.region, 200).trim(),
    service: clampText(raw.service, 200).trim(),
    subscription: clampText(raw.subscription, 200).trim(),
    resourceGroup: clampText(raw.resourceGroup, 200).trim(),
    uid: clampText(raw.uid, 300).trim(),
    resourceId: clampText(raw.resourceId, 500).trim(),
    portalLink: clampText(raw.portalLink, 500).trim()
  };
}

function sanitizeControlRef(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const benchmarkId = clampText(raw.benchmarkId, 180).trim();
  const requirementId = clampText(raw.requirementId, 80).trim();
  if (!BENCHMARK_ID.test(benchmarkId) || benchmarkId.includes('..')) return null;
  if (!REQUIREMENT_ID.test(requirementId)) return null;
  const label = clampText(raw.label, 240).trim();
  return { benchmarkId, requirementId, label };
}

function sanitizeCustomFinding(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  if (!CUSTOM_ID.test(raw.id)) return null;
  const title = clampText(raw.title, 200).trim();
  if (!title) return null;
  const severity = SEVERITIES.has(raw.severity) ? raw.severity : 'medium';
  const assets = [];
  for (const asset of Array.isArray(raw.assets) ? raw.assets.slice(0, 100) : []) {
    const clean = sanitizeAsset(asset);
    if (clean) assets.push(clean);
  }
  const controls = [];
  const seen = new Set();
  for (const control of Array.isArray(raw.controls) ? raw.controls.slice(0, 40) : []) {
    const clean = sanitizeControlRef(control);
    if (!clean) continue;
    const key = reviewKey(clean.benchmarkId, clean.requirementId);
    if (seen.has(key)) continue;
    seen.add(key);
    controls.push(clean);
  }
  const observations = [];
  for (const item of Array.isArray(raw.observations) ? raw.observations.slice(0, 20) : []) {
    const text = clampText(item, 4000).trim();
    if (text) observations.push(text);
  }
  const now = new Date().toISOString();
  return {
    id: raw.id,
    title,
    severity,
    cloud: clampText(raw.cloud, 40).trim() || 'Custom',
    service: clampText(raw.service, 120).trim(),
    details: clampText(raw.details, 16000),
    impact: clampText(raw.impact, 16000),
    remediation: clampText(raw.remediation, 16000),
    observations,
    controls,
    assets,
    createdAt: clampText(raw.createdAt, 40) || now,
    updatedAt: now
  };
}

function sanitizeCustomFindings(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  const seen = new Set();
  for (const item of value.slice(0, 200)) {
    const clean = sanitizeCustomFinding(item);
    if (!clean || seen.has(clean.id)) continue;
    seen.add(clean.id);
    out.push(clean);
  }
  return out;
}

function findingEditKey(key) {
  if (typeof key !== 'string') return '';
  const id = key.trim();
  if (!id || id.length > 300 || id.includes('..') || /[\u0000\r\n]/.test(id)) return '';
  return id;
}

function sanitizeFindingEdit(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const edit = {};
  if (typeof raw.title === 'string') {
    const title = clampText(raw.title, 200).trim();
    if (title) edit.title = title;
  }
  if (SEVERITIES.has(raw.severity)) edit.severity = raw.severity;
  if (typeof raw.cloud === 'string') edit.cloud = clampText(raw.cloud, 40).trim();
  if (typeof raw.service === 'string') edit.service = clampText(raw.service, 120).trim();
  if (typeof raw.details === 'string') edit.details = clampText(raw.details, 16000);
  if (typeof raw.impact === 'string') edit.impact = clampText(raw.impact, 16000);
  if (typeof raw.remediation === 'string') edit.remediation = clampText(raw.remediation, 16000);
  if (Array.isArray(raw.observations)) {
    const observations = [];
    for (const item of raw.observations.slice(0, 20)) {
      const text = clampText(item, 4000).trim();
      if (text) observations.push(text);
    }
    edit.observations = observations;
  }
  if (Array.isArray(raw.assets)) {
    const assets = [];
    for (const asset of raw.assets.slice(0, 100)) {
      const clean = sanitizeAsset(asset);
      if (clean) assets.push(clean);
    }
    if (assets.length) edit.assets = assets;
  }
  if (Array.isArray(raw.controls)) {
    const controls = [];
    const seen = new Set();
    for (const control of raw.controls.slice(0, 40)) {
      const clean = sanitizeControlRef(control);
      if (!clean) continue;
      const key = reviewKey(clean.benchmarkId, clean.requirementId);
      if (seen.has(key)) continue;
      seen.add(key);
      controls.push(clean);
    }
    edit.controls = controls;
  }
  return Object.keys(edit).length ? edit : null;
}

function sanitizeFindingEdits(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out = {};
  let count = 0;
  for (const [key, raw] of Object.entries(value)) {
    if (count >= 2000) break;
    const id = findingEditKey(key);
    if (!id) continue;
    const edit = sanitizeFindingEdit(raw);
    if (!edit) continue;
    out[id] = edit;
    count += 1;
  }
  return out;
}

function applyFindingEdit(finding, edit) {
  if (!edit || finding.source === 'custom') return finding;
  const next = { ...finding, edited: true };
  if (edit.title) next.title = edit.title;
  if (edit.severity) next.severity = edit.severity;
  if (edit.cloud) next.cloud = edit.cloud;
  if (Object.prototype.hasOwnProperty.call(edit, 'service')) next.service = edit.service;
  if (Object.prototype.hasOwnProperty.call(edit, 'details')) {
    next.details = edit.details;
    next.description = edit.details;
  }
  if (Object.prototype.hasOwnProperty.call(edit, 'impact')) {
    next.impact = edit.impact;
    next.risk = edit.impact;
  }
  if (Object.prototype.hasOwnProperty.call(edit, 'remediation')) next.remediation = edit.remediation;
  if (Object.prototype.hasOwnProperty.call(edit, 'observations')) next.observations = edit.observations;
  if (edit.assets) {
    const assets = edit.assets.map(asset => ({ ...asset, absent: false }));
    next.assets = assets;
    next.failCount = assets.filter(asset => asset.status === 'FAIL').length;
    next.passCount = assets.filter(asset => asset.status === 'PASS').length;
    next.manualCount = assets.filter(asset => asset.status === 'MANUAL').length;
    next.subscriptions = [...new Set(assets.map(asset => asset.subscription).filter(Boolean))];
    next.resourceGroups = [...new Set(assets.map(asset => asset.resourceGroup).filter(Boolean))];
  }
  if (Object.prototype.hasOwnProperty.call(edit, 'controls')) {
    next.controlRefs = edit.controls;
    next.controlsEdited = true;
  }
  return next;
}

function buildFindingEdit(body, existing) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { error: 'Invalid request.' };
  const source = { ...(existing || {}) };
  if (Object.prototype.hasOwnProperty.call(body, 'title')) {
    const title = clampText(body.title, 200).trim();
    if (title) source.title = title;
    else delete source.title;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'severity')) {
    if (!SEVERITIES.has(body.severity)) return { error: 'Unknown severity.' };
    source.severity = body.severity;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'cloud')) source.cloud = clampText(body.cloud, 40).trim();
  if (Object.prototype.hasOwnProperty.call(body, 'service')) source.service = clampText(body.service, 120).trim();
  if (Object.prototype.hasOwnProperty.call(body, 'details')) source.details = clampText(body.details, 16000);
  if (Object.prototype.hasOwnProperty.call(body, 'impact')) source.impact = clampText(body.impact, 16000);
  if (Object.prototype.hasOwnProperty.call(body, 'remediation')) source.remediation = clampText(body.remediation, 16000);
  if (Object.prototype.hasOwnProperty.call(body, 'observations')) {
    if (!Array.isArray(body.observations)) return { error: 'Observations must be a list.' };
    source.observations = body.observations;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'assets')) {
    if (!Array.isArray(body.assets)) return { error: 'Assets must be a list.' };
    for (const asset of body.assets) {
      if (!asset || typeof asset !== 'object' || Array.isArray(asset) || !String(asset.name || '').trim()) {
        return { error: 'Each asset needs a name.' };
      }
      if (asset.status && !ASSET_STATUSES.has(asset.status)) {
        return { error: 'Asset status must be FAIL, PASS, or MANUAL.' };
      }
    }
    if (!body.assets.length) return { error: 'Add at least one asset.' };
    source.assets = body.assets;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'controls')) {
    if (!Array.isArray(body.controls)) return { error: 'Controls must be a list.' };
    for (const control of body.controls) {
      if (!sanitizeControlRef(control)) return { error: 'A control needs a benchmark id and a requirement id.' };
    }
    source.controls = body.controls;
  }
  return { edit: sanitizeFindingEdit(source) };
}

function sanitizeControlReviews(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out = {};
  let count = 0;
  for (const [key, raw] of Object.entries(value)) {
    if (count >= 2000) break;
    const parts = splitReviewKey(key);
    if (!parts || !raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const status = CONTROL_STATUSES.has(raw.status) ? raw.status : '';
    const note = clampText(raw.note, 8000);
    if (!status && !note) continue;
    const updatedAt = clampText(raw.updatedAt, 40);
    out[reviewKey(parts.benchmarkId, parts.requirementId)] = {
      status,
      note,
      updatedAt: Number.isFinite(Date.parse(updatedAt)) ? updatedAt : new Date().toISOString()
    };
    count += 1;
  }
  return out;
}

function readJson(fp, fallback = null) {
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return fallback; }
}

function asItems(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.findings)) return data.findings;
  if (Array.isArray(data?.results)) return data.results;
  return [];
}

function concatScanItems(groups) {
  const seen = new Set();
  const out = [];
  for (const items of groups) {
    const inThisScan = new Set();
    for (const item of items) {
      const uid = item?.finding_info?.uid;
      if (uid && seen.has(uid)) continue;
      out.push(item);
      if (uid) inThisScan.add(uid);
    }
    for (const uid of inThisScan) seen.add(uid);
  }
  return out;
}

function safeScanId(id) {
  return typeof id === 'string' && /^scan_[A-Za-z0-9_-]+$/.test(id);
}

function loadEvidence(projectPath, state) {
  const scans = Array.isArray(state.scans) ? state.scans : [];
  if (!scans.length) {
    return {
      items: asItems(readJson(path.join(projectPath, 'raw.json'), null)),
      baselineItems: [],
      hasRetest: false
    };
  }
  const scansDir = path.join(projectPath, 'scans');
  const replaced = new Set(scans.map(scan => scan.replaces).filter(Boolean));
  const current = scans.filter(scan => !replaced.has(scan.id));
  const baseline = scans.filter(scan => current.some(item => item.replaces === scan.id));
  const readScan = scan => {
    if (!safeScanId(scan.id)) return [];
    return asItems(readJson(path.join(scansDir, `${scan.id}.json`), []));
  };
  return {
    items: concatScanItems(current.map(readScan)),
    baselineItems: concatScanItems(baseline.map(readScan)),
    hasRetest: baseline.length > 0
  };
}

function deriveCheckId(uid) {
  if (!uid) return '';
  const match = String(uid).match(/^(prowler-(?:aws|azure|gcp|kubernetes|oraclecloud|alibabacloud)-[a-z][a-z0-9_]*)/i);
  if (match) return match[1].toLowerCase();
  return String(uid).split('-').slice(0, 3).join('-').toLowerCase();
}

function normalizeSeverity(value) {
  if (value == null) return 'informational';
  const text = String(value).toLowerCase().trim();
  if (text === '1') return 'informational';
  if (text === '2') return 'low';
  if (text === '3') return 'medium';
  if (text === '4') return 'high';
  if (text === '5') return 'critical';
  if (text.startsWith('info')) return 'informational';
  if (text.startsWith('low')) return 'low';
  if (text.startsWith('med')) return 'medium';
  if (text.startsWith('high')) return 'high';
  if (text.startsWith('crit')) return 'critical';
  return 'informational';
}

function normalizeStatus(value) {
  if (value == null) return 'FAIL';
  const text = String(value).toUpperCase().trim();
  if (text === 'PASS' || text === 'PASSED' || text === '1' || text === 'TRUE') return 'PASS';
  if (text === 'MANUAL') return 'MANUAL';
  return 'FAIL';
}

function detectCloud(item) {
  const provider = String(item.cloud?.provider || '').toLowerCase();
  if (provider === 'aws') return 'AWS';
  if (provider === 'azure') return 'Azure';
  if (provider === 'gcp') return 'GCP';
  const unmapped = String(item.unmapped?.provider || '').toLowerCase();
  if (unmapped === 'aws') return 'AWS';
  if (unmapped === 'azure') return 'Azure';
  if (unmapped === 'gcp') return 'GCP';
  const uid = String(item.finding_info?.uid || '').toLowerCase();
  if (uid.startsWith('prowler-aws')) return 'AWS';
  if (uid.startsWith('prowler-azure')) return 'Azure';
  if (uid.startsWith('prowler-gcp')) return 'GCP';
  return 'Unknown';
}

function extractService(item) {
  const rawType = item.resources?.[0]?.type || '';
  const fromType = rawType ? rawType.split('/').slice(0, 2).join('/') : '';
  return item.unmapped?.service_name || item.unmapped?.resource_type || fromType || item.cloud?.service || '';
}

function extractSubscription(item) {
  return item.cloud?.account?.name || item.cloud?.account?.uid || item.unmapped?.account_id || item.unmapped?.subscription_id || item.unmapped?.project_id || '';
}

function extractResourceGroup(item) {
  const resourceId = item.resources?.[0]?.data?.metadata?.resource_id || '';
  const match = String(resourceId).match(/resourceGroups\/([^/]+)/i);
  if (match) return match[1];
  return item.unmapped?.resource_group || item.unmapped?.resource_group_name || item.cloud?.resource_group || '';
}

function extractAssetName(item) {
  if (item.resources?.length) {
    const resource = item.resources[0];
    return resource.data?.metadata?.name || resource.name || resource.uid || 'Unknown';
  }
  return item.unmapped?.resource_name || 'Unknown';
}

function extractControls(item) {
  const controls = [];
  const source = item.unmapped?.compliance || item.compliance || null;
  if (source && typeof source === 'object') {
    for (const [framework, ids] of Object.entries(source)) {
      if (Array.isArray(ids)) ids.forEach(id => controls.push(`${framework}: ${id}`));
      else if (typeof ids === 'string') controls.push(`${framework}: ${ids}`);
    }
  }
  return [...new Set(controls)].filter(Boolean);
}

function consolidateFindings(data, multiCloud = false) {
  const items = asItems(data);
  const map = new Map();
  for (const item of items) {
    const rawUid = item.finding_info?.uid || '';
    const checkId = item.finding_info?.check_id
      || item.unmapped?.check_id
      || item.metadata?.event_code
      || deriveCheckId(rawUid)
      || item.finding_info?.title
      || 'unknown';
    const observation = item.status_detail || item.unmapped?.status_detail || '';
    const title = item.finding_info?.title || item.title || checkId;
    const status = normalizeStatus(item.status_code || item.unmapped?.status_code || item.unmapped?.check_result || item.status_id || item.status);
    const severity = normalizeSeverity(item.severity || item.severity_id);
    const cloud = detectCloud(item);
    const key = multiCloud ? `${cloud}::${checkId}` : checkId;
    const service = extractService(item);
    const subscription = extractSubscription(item);
    const resourceGroup = extractResourceGroup(item);
    const risk = item.risk_details || item.unmapped?.risk_details || item.finding_info?.desc || '';
    const description = item.finding_info?.desc || '';
    const remediation = item.remediation?.desc || item.unmapped?.remediation_text || (typeof item.remediation === 'string' ? item.remediation : '') || '';
    const assetName = extractAssetName(item);
    const region = item.cloud?.region || item.resources?.[0]?.region || item.unmapped?.region || '';

    if (!map.has(key)) {
      map.set(key, {
        id: key,
        source: 'prowler',
        title,
        severity,
        cloud,
        service,
        description,
        risk,
        remediation,
        controls: extractControls(item),
        observations: new Set(),
        assets: [],
        subscriptions: new Set(),
        resourceGroups: new Set(),
        failCount: 0,
        passCount: 0,
        manualCount: 0
      });
    }
    const finding = map.get(key);
    if (!finding.risk && risk) finding.risk = risk;
    if (!finding.description && description) finding.description = description;
    if (!finding.remediation && remediation) finding.remediation = remediation;
    if (!finding.controls.length) finding.controls = extractControls(item);
    if (observation) finding.observations.add(observation);
    if (subscription) finding.subscriptions.add(subscription);
    if (resourceGroup) finding.resourceGroups.add(resourceGroup);
    if (status === 'PASS') finding.passCount += 1;
    else if (status === 'MANUAL') finding.manualCount += 1;
    else finding.failCount += 1;
    finding.assets.push({
      name: assetName,
      status,
      region,
      subscription,
      resourceGroup,
      service
    });
  }

  return [...map.values()].map(finding => ({
    ...finding,
    observations: [...finding.observations],
    subscriptions: [...finding.subscriptions],
    resourceGroups: [...finding.resourceGroups]
  }));
}

function firstCloud(items) {
  for (const item of items) {
    const cloud = detectCloud(item);
    if (cloud && cloud !== 'Unknown') return cloud;
  }
  return '';
}

function matchPrevAsset(asset, prevAssets) {
  if (asset.name) return prevAssets.find(candidate => candidate.name === asset.name) || null;
  return null;
}

function assetRound(prev, nowStatus) {
  const prevFail = !!(prev && prev.status === 'FAIL');
  const nowFail = nowStatus === 'FAIL';
  if (prevFail && nowFail) return 'open';
  if (prevFail && !nowFail) return 'closed';
  if (nowFail && !prevFail) return 'new';
  return '';
}

function annotateRetest(findings, baselineFindings) {
  const base = new Map((baselineFindings || []).map(finding => [finding.id, finding]));
  const seen = new Set(findings.map(finding => finding.id));
  const out = findings.map(finding => {
    const prev = base.get(finding.id);
    const prevFail = !!(prev && prev.failCount > 0);
    const nowFail = finding.failCount > 0;
    let round = '';
    if (prevFail && nowFail) round = 'open';
    else if (prevFail && !nowFail) round = 'closed';
    else if (!prevFail && nowFail) round = 'new';
    const prevAssets = prev?.assets || [];
    const assets = finding.assets.map(asset => ({
      ...asset,
      round: assetRound(matchPrevAsset(asset, prevAssets), asset.status)
    }));
    for (const asset of prevAssets) {
      if (asset.status !== 'FAIL') continue;
      if (assets.some(candidate => asset.name && candidate.name === asset.name)) continue;
      assets.push({ ...asset, round: 'closed', absent: true });
    }
    return { ...finding, round, assets };
  });
  for (const prev of baselineFindings || []) {
    if (seen.has(prev.id) || !(prev.failCount > 0)) continue;
    out.push({
      ...prev,
      failCount: 0,
      passCount: 0,
      manualCount: 0,
      round: 'closed',
      assets: (prev.assets || []).filter(asset => asset.status === 'FAIL').map(asset => ({
        ...asset,
        round: 'closed',
        absent: true
      }))
    });
  }
  return out;
}

function getShortCheckId(id) {
  if (!id) return '';
  let raw = String(id);
  const sep = raw.indexOf('::');
  if (sep !== -1) raw = raw.slice(sep + 2);
  const match = raw.match(/^prowler-(?:aws|azure|gcp|kubernetes|oraclecloud|alibabacloud)-(.+)$/i);
  return match ? match[1].toLowerCase() : raw.toLowerCase();
}

function buildRemediationFromMeta(meta, fallback = '') {
  if (!meta?.Remediation) return fallback || '';
  const parts = [];
  const recommendation = meta.Remediation.Recommendation?.Text;
  if (recommendation) parts.push(recommendation);
  const code = meta.Remediation.Code || {};
  for (const [label, value] of Object.entries(code)) {
    if (value) parts.push(`### ${label}\n\n${value}`);
  }
  if (!parts.length && fallback) parts.push(fallback);
  return parts.join('\n\n');
}

function lookupMetadata(index, id) {
  if (!index || !id) return null;
  const raw = String(id).toLowerCase();
  return index[raw] || index[getShortCheckId(raw)] || null;
}

function enrichFinding(finding, index) {
  const meta = lookupMetadata(index, finding.id) || lookupMetadata(index, getShortCheckId(finding.id));
  finding.details = finding.description || '';
  finding.impact = finding.risk || '';
  if (!meta) return finding;
  finding.title = meta.CheckTitle || finding.title;
  finding.details = meta.Description || finding.details;
  finding.impact = meta.Risk || finding.impact;
  if (meta.Severity) finding.severity = normalizeSeverity(meta.Severity);
  if (meta.ServiceName) finding.service = meta.ServiceName;
  finding.remediation = buildRemediationFromMeta(meta, finding.remediation);
  finding.shortCheckId = meta.CheckID || getShortCheckId(finding.id);
  return finding;
}

function sortFindings(findings) {
  const order = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  return findings.sort((a, b) =>
    (order[a.severity] ?? 5) - (order[b.severity] ?? 5) || (b.failCount - a.failCount)
  );
}

function rewriteReviewMap(map, findings, multi, originalCloud, clouds) {
  const next = {};
  for (const [key, value] of Object.entries(map || {})) {
    if (typeof key === 'string' && key.startsWith('custom_')) {
      next[key] = value;
      continue;
    }
    const sep = key.indexOf('::');
    if (multi && sep === -1) {
      const matches = findings.filter(finding => finding.source !== 'custom' && finding.id.endsWith(`::${key}`));
      const matchClouds = [...new Set(matches.map(finding => finding.id.slice(0, finding.id.length - key.length - 2)))];
      const cloud = matchClouds.length === 1 ? matchClouds[0] : (originalCloud || clouds[0] || '');
      next[cloud ? `${cloud}::${key}` : key] = value;
    } else if (!multi && clouds.length === 1 && sep !== -1 && key.startsWith(`${clouds[0]}::`)) {
      next[key.slice(clouds[0].length + 2)] = value;
    } else {
      next[key] = value;
    }
  }
  return next;
}

function alignReviewState(findings, state, originalCloud) {
  const clouds = [...new Set(findings.filter(finding => finding.source !== 'custom' && finding.cloud && finding.cloud !== 'Unknown').map(finding => finding.cloud))];
  const multi = clouds.length > 1;
  return {
    ...state,
    statuses: rewriteReviewMap(state.statuses, findings, multi, originalCloud, clouds),
    reasons: rewriteReviewMap(state.reasons, findings, multi, originalCloud, clouds),
    notes: rewriteReviewMap(state.notes, findings, multi, originalCloud, clouds),
    findingEdits: rewriteReviewMap(state.findingEdits, findings, multi, originalCloud, clouds)
  };
}

function materializeCustom(record) {
  const assets = (record.assets || []).map(asset => ({ ...asset, absent: false }));
  return {
    id: record.id,
    source: 'custom',
    title: record.title,
    severity: record.severity || 'medium',
    cloud: record.cloud || 'Custom',
    service: record.service || '',
    description: record.details || '',
    details: record.details || '',
    risk: record.impact || '',
    impact: record.impact || '',
    remediation: record.remediation || '',
    observations: record.observations || [],
    controls: (record.controls || []).map(control => control.label || `${control.benchmarkId}: ${control.requirementId}`),
    controlRefs: record.controls || [],
    assets,
    subscriptions: [...new Set(assets.map(asset => asset.subscription).filter(Boolean))],
    resourceGroups: [...new Set(assets.map(asset => asset.resourceGroup).filter(Boolean))],
    failCount: assets.filter(asset => asset.status === 'FAIL').length,
    passCount: assets.filter(asset => asset.status === 'PASS').length,
    manualCount: assets.filter(asset => asset.status === 'MANUAL').length,
    round: ''
  };
}

function checkMap(findings) {
  const map = new Map();
  for (const finding of findings) {
    if (finding.source === 'custom') continue;
    map.set(getShortCheckId(finding.id), finding);
    map.set(String(finding.id).toLowerCase(), finding);
    if (finding.shortCheckId) map.set(String(finding.shortCheckId).toLowerCase(), finding);
  }
  return map;
}

function requirementResult(requirement, findings) {
  const names = requirement?.Checks || [];
  const linked = [];
  const seen = new Set();
  let failCount = 0;
  let passCount = 0;
  let manualCount = 0;
  const byCheck = checkMap(findings);
  for (const name of names) {
    const finding = byCheck.get(String(name).toLowerCase());
    if (!finding || seen.has(finding.id)) continue;
    seen.add(finding.id);
    linked.push(finding);
    failCount += finding.failCount || 0;
    passCount += finding.passCount || 0;
    manualCount += finding.manualCount || 0;
  }
  let scannerStatus = 'n/a';
  if (!names.length || !linked.length) scannerStatus = 'n/a';
  else if (failCount > 0) scannerStatus = 'fail';
  else if (passCount > 0) scannerStatus = 'pass';
  else if (manualCount > 0) scannerStatus = 'manual';
  return { scannerStatus, failCount, passCount, manualCount, findings: linked };
}

function customLinks(requirementId, benchmarkId, findings) {
  return findings.filter(finding =>
    finding.source === 'custom' &&
    (finding.controlRefs || []).some(control =>
      control.benchmarkId === benchmarkId && control.requirementId === requirementId
    )
  );
}

function reviewOf(state, benchmarkId, requirementId) {
  const raw = state.controlReviews?.[reviewKey(benchmarkId, requirementId)];
  const status = raw && CONTROL_STATUSES.has(raw.status) ? raw.status : '';
  const note = raw?.note || '';
  return {
    status,
    note,
    validated: Boolean(status),
    updatedAt: raw?.updatedAt || null
  };
}

function relatedControls(finding, benchmarks, state, findings) {
  const rows = [];
  const seen = new Set();
  const short = getShortCheckId(finding.id);
  const refs = new Set((finding.controlRefs || []).map(control => reviewKey(control.benchmarkId, control.requirementId)));
  for (const benchmark of benchmarks) {
    for (const requirement of benchmark.data?.Requirements || []) {
      const key = reviewKey(benchmark.id, requirement.Id);
      const byCheck = !finding.controlsEdited && finding.source !== 'custom' && (requirement.Checks || []).some(check => String(check).toLowerCase() === short);
      const byRef = refs.has(key);
      if (!byCheck && !byRef) continue;
      if (seen.has(key)) continue;
      seen.add(key);
      const result = requirementResult(requirement, findings);
      const review = reviewOf(state, benchmark.id, requirement.Id);
      rows.push({
        benchmarkId: benchmark.id,
        benchmark: benchmark.name || benchmark.id,
        requirementId: requirement.Id,
        description: requirement.Description || '',
        scannerStatus: result.scannerStatus,
        validated: review.validated,
        reviewStatus: review.status,
        note: review.note
      });
    }
  }
  return rows;
}

function touched(state, finding) {
  if (finding.source === 'custom') return true;
  if (state.findingEdits?.[finding.id]) return true;
  return Boolean(state.statuses?.[finding.id] || state.reasons?.[finding.id] || state.notes?.[finding.id]);
}

function publicAsset(asset) {
  return {
    name: asset.name || '',
    status: asset.status || '',
    region: asset.region || '',
    service: asset.service || '',
    subscription: asset.subscription || '',
    resourceGroup: asset.resourceGroup || '',
    round: asset.round || '',
    absent: Boolean(asset.absent)
  };
}

function publicFinding(finding, state, benchmarks, findings, { includeAssets = false } = {}) {
  const controls = relatedControls(finding, benchmarks, state, findings);
  const failedNames = (finding.assets || []).filter(asset => asset.status === 'FAIL' && !asset.absent).map(asset => asset.name).filter(Boolean);
  const view = {
    id: finding.id,
    source: finding.source || 'prowler',
    title: finding.title || finding.id,
    severity: finding.severity || 'informational',
    cloud: finding.cloud || '',
    service: finding.service || '',
    round: finding.round || '',
    scanner: {
      fail: finding.failCount || 0,
      pass: finding.passCount || 0,
      manual: finding.manualCount || 0
    },
    review: {
      status: state.statuses?.[finding.id] || '',
      reason: state.reasons?.[finding.id] || '',
      note: state.notes?.[finding.id] || '',
      touched: touched(state, finding)
    },
    scanControls: finding.source === 'custom' ? [] : (finding.controls || []),
    controls,
    failedAssetNames: failedNames.slice(0, 25),
    failedAssetCount: failedNames.length,
    edited: Boolean(state.findingEdits?.[finding.id])
  };
  if (includeAssets) {
    view.details = finding.details || finding.description || '';
    view.impact = finding.impact || finding.risk || '';
    view.remediation = finding.remediation || '';
    view.observations = finding.observations || [];
    view.assets = (finding.assets || []).map(publicAsset);
    if (finding.source === 'custom') {
      view.custom = {
        controls: finding.controlRefs || [],
        cloud: finding.cloud || 'Custom',
        service: finding.service || ''
      };
    }
  }
  return view;
}

function attributeOf(requirement) {
  return requirement.Attributes?.[0] || {};
}

function publicControl(benchmark, requirement, findings, state) {
  const result = requirementResult(requirement, findings);
  const review = reviewOf(state, benchmark.id, requirement.Id);
  const attribute = attributeOf(requirement);
  const linked = [
    ...result.findings.map(finding => ({
      id: finding.id,
      source: 'prowler',
      title: finding.title,
      reviewStatus: state.statuses?.[finding.id] || '',
      reason: state.reasons?.[finding.id] || '',
      note: state.notes?.[finding.id] || '',
      touched: touched(state, finding),
      failCount: finding.failCount || 0,
      passCount: finding.passCount || 0,
      manualCount: finding.manualCount || 0
    })),
    ...customLinks(requirement.Id, benchmark.id, findings).map(finding => ({
      id: finding.id,
      source: 'custom',
      title: finding.title,
      reviewStatus: state.statuses?.[finding.id] || '',
      reason: state.reasons?.[finding.id] || '',
      note: state.notes?.[finding.id] || '',
      touched: true,
      failCount: finding.failCount || 0,
      passCount: finding.passCount || 0,
      manualCount: finding.manualCount || 0
    }))
  ];
  return {
    id: requirement.Id,
    description: requirement.Description || '',
    section: attribute.Section || '',
    subsection: attribute.SubSection || '',
    profile: attribute.Profile || attribute.Type || '',
    checks: requirement.Checks || [],
    scannerStatus: result.scannerStatus,
    failCount: result.failCount,
    passCount: result.passCount,
    manualCount: result.manualCount,
    review,
    findings: linked
  };
}

function benchmarkSummary(benchmark) {
  return {
    id: benchmark.id,
    name: benchmark.data?.Name || benchmark.id,
    framework: benchmark.data?.Framework || '',
    version: benchmark.data?.Version || '',
    provider: benchmark.data?.Provider || ''
  };
}

function buildProjectReview({ projectPath, state, metadataIndex, benchmarks }) {
  const evidence = loadEvidence(projectPath, state || {});
  const clouds = new Set(evidence.items.map(detectCloud).filter(cloud => cloud && cloud !== 'Unknown'));
  let findings = consolidateFindings(evidence.items, clouds.size > 1);
  if (evidence.hasRetest) {
    const baseline = consolidateFindings(evidence.baselineItems, clouds.size > 1);
    findings = annotateRetest(findings, baseline);
  }
  findings = findings.map(finding => enrichFinding(finding, metadataIndex || {}));
  const findingEdits = sanitizeFindingEdits(state?.findingEdits);
  findings = findings.map(finding => applyFindingEdit(finding, findingEdits[finding.id]));
  const custom = sanitizeCustomFindings(state?.customFindings).map(materializeCustom);
  findings = sortFindings([...findings, ...custom]);
  const aligned = alignReviewState(findings, {
    ...state,
    statuses: state?.statuses || {},
    reasons: state?.reasons || {},
    notes: state?.notes || {},
    controlReviews: sanitizeControlReviews(state?.controlReviews),
    customFindings: sanitizeCustomFindings(state?.customFindings),
    findingEdits
  }, firstCloud(evidence.items));
  return { findings, state: aligned, benchmarks: benchmarks || [] };
}

function newCustomId() {
  const crypto = require('crypto');
  return `custom_${crypto.randomBytes(16).toString('hex')}`;
}

function textField(body, key, max) {
  if (!Object.prototype.hasOwnProperty.call(body, key)) return undefined;
  return clampText(body[key], max);
}

function buildCustomRecord(body, existing) {
  const now = new Date().toISOString();
  const source = { ...(existing || {}) };
  const assign = (key) => {
    if (Object.prototype.hasOwnProperty.call(body, key)) source[key] = body[key];
  };
  source.id = existing?.id || newCustomId();
  source.createdAt = existing?.createdAt || now;
  ['title', 'cloud', 'service', 'details', 'impact', 'remediation'].forEach(assign);
  if (Object.prototype.hasOwnProperty.call(body, 'severity')) {
    if (!SEVERITIES.has(body.severity)) return { error: 'Unknown severity.' };
    source.severity = body.severity;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'assets')) {
    if (!Array.isArray(body.assets)) return { error: 'Assets must be a list.' };
    for (const asset of body.assets) {
      if (!asset || typeof asset !== 'object' || Array.isArray(asset) || !String(asset.name || '').trim()) {
        return { error: 'Each asset needs a name.' };
      }
      if (asset.status && !ASSET_STATUSES.has(asset.status)) {
        return { error: 'Asset status must be FAIL, PASS, or MANUAL.' };
      }
    }
    source.assets = body.assets;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'controls')) {
    if (!Array.isArray(body.controls)) return { error: 'Controls must be a list.' };
    for (const control of body.controls) {
      if (!sanitizeControlRef(control)) return { error: 'A control needs a benchmark id and a requirement id.' };
    }
    source.controls = body.controls;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'observations')) {
    if (!Array.isArray(body.observations)) return { error: 'Observations must be a list.' };
    source.observations = body.observations;
  }
  const clean = sanitizeCustomFinding(source);
  if (!clean) return { error: 'A custom finding needs a title.' };
  if (!clean.assets.length) return { error: 'Add at least one asset.' };
  return { finding: clean };
}

function setMapValue(map, id, value) {
  const next = { ...(map || {}) };
  if (value) next[id] = value;
  else delete next[id];
  return next;
}

module.exports = {
  FINDING_STATUSES,
  CONTROL_STATUSES,
  SEVERITIES,
  withStateLock,
  reviewKey,
  splitReviewKey,
  sanitizeCustomFindings,
  sanitizeControlReviews,
  sanitizeControlRef,
  buildProjectReview,
  publicFinding,
  publicControl,
  benchmarkSummary,
  buildCustomRecord,
  buildFindingEdit,
  sanitizeFindingEdits,
  setMapValue,
  textField,
  newCustomId,
  BENCHMARK_ID,
  REQUIREMENT_ID,
  readJson
};
