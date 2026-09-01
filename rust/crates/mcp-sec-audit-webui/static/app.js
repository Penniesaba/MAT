'use strict';

const $ = (id) => document.getElementById(id);

let ws = null;
const logs = new Map();  // repo -> array of "level: line" strings
const repos = new Map(); // repo -> bar element

// ---- WebSocket: snapshot frame first, then live event frames --------------

function connect() {
  ws = new WebSocket(
    `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/events`,
  );
  ws.onmessage = (e) => {
    let msg;
    try {
      msg = JSON.parse(e.data);
    } catch {
      return; // ignore malformed frames
    }
    if (msg.type === 'snapshot') renderSnapshot(msg.data);
    else if (msg.type === 'event') handleEvent(msg.data);
  };
  ws.onclose = () => setTimeout(connect, 1000);
}

// ---- Live events. `AnalysisEvent` is externally tagged, so `ev` carries a
// ---- single key named after the variant (BatchStarted / RepoStarted /
// ---- StageProgress / Log / RepoFinished). --------------------------------

function handleEvent(ev) {
  if (ev.BatchStarted) {
    for (const name of ev.BatchStarted.repo_names) resetRepo(name);
    return;
  }
  if (ev.RepoStarted) {
    resetRepo(ev.RepoStarted.repo);
    return;
  }
  if (ev.StageProgress) {
    const el = ensureRepo(ev.StageProgress.repo);
    setPercent(el, ev.StageProgress.percent);
    return;
  }
  if (ev.Log) {
    const repo = ev.Log.repo;
    if (!logs.has(repo)) logs.set(repo, []);
    logs.get(repo).push(`${ev.Log.level}: ${ev.Log.line}`);
    if (!$('modal').hidden && $('modal-title').textContent === repo) {
      renderModal(repo);
    }
    return;
  }
  if (ev.RepoFinished) {
    finishRepo(ensureRepo(ev.RepoFinished.repo), ev.RepoFinished.status);
  }
}

// ---- Snapshot replay ------------------------------------------------------
// `RunSnapshot` = { batch_id, repos: {name: RepoProgress}, logs: {name: [[level,line],...]} }.
// `RepoProgress.status` is `null` while a repo is in-flight.

function renderSnapshot(snap) {
  for (const [name, p] of Object.entries(snap.repos || {})) {
    renderProgress(ensureRepo(name), p);
  }
  for (const [name, lines] of Object.entries(snap.logs || {})) {
    logs.set(name, lines.map(([level, line]) => `${level}: ${line}`));
  }
}

function renderProgress(el, p) {
  setPercent(el, p.percent);
  if (p.status === null || p.status === undefined) {
    // In-flight: status is null (NOT "cancelled"). Show progress.
    el.classList.remove('done', 'failed', 'cancelled');
    el.querySelector('.repo-status').textContent = `${p.percent || 0}%`;
  } else {
    finishRepo(el, p.status);
  }
}

// ---- Repo bar helpers -----------------------------------------------------

function ensureRepo(name) {
  if (repos.has(name)) return repos.get(name);
  const el = document.createElement('div');
  el.className = 'repo';
  el.innerHTML =
    '<div class="repo-head"><span class="repo-name"></span><span class="repo-status"></span></div>' +
    '<div class="bar"><div class="fill"></div></div>';
  el.querySelector('.repo-name').textContent = name;
  el.onclick = () => openModal(name);
  $('repos').appendChild(el);
  repos.set(name, el);
  return el;
}

function resetRepo(name) {
  const el = ensureRepo(name);
  el.classList.remove('done', 'failed', 'cancelled');
  el.querySelector('.fill').style.width = '0%';
  el.querySelector('.repo-status').textContent = 'in progress';
}

function setPercent(el, percent) {
  el.querySelector('.fill').style.width = `${percent || 0}%`;
}

function finishRepo(el, status) {
  el.classList.remove('done', 'failed', 'cancelled');
  el.classList.add(
    status === 'ok' ? 'done' : status === 'failed' ? 'failed' : 'cancelled',
  );
  el.querySelector('.repo-status').textContent = status;
  el.querySelector('.fill').style.width = '100%';
}

// ---- Detail modal (1/3 x 4/5, centered via CSS) ---------------------------

function openModal(name) {
  $('modal').hidden = false;
  $('modal-title').textContent = name;
  renderModal(name);
}

function renderModal(name) {
  $('modal-logs').textContent = (logs.get(name) || []).join('\n');
}

$('modal-close').onclick = () => {
  $('modal').hidden = true;
};

// ---- Config CRUD ----------------------------------------------------------

$('import-btn').onclick = () => $('file').click();
$('file').onchange = async () => {
  const file = $('file').files[0];
  if (!file) return;
  const text = await file.text();
  $('toml').value = text;
  await importToml(text);
};

async function importToml(text) {
  const err = $('config-error');
  const r = await fetch('/api/import', { method: 'POST', body: text });
  if (!r.ok) {
    err.hidden = false;
    err.textContent = await r.text();
  } else {
    err.hidden = true;
  }
}

$('export-btn').onclick = async () => {
  const r = await fetch('/api/config/export');
  if (r.ok) $('toml').value = await r.text();
};

$('run-btn').onclick = async () => {
  const text = $('toml').value;
  if (text.trim()) await importToml(text);
  await fetch('/api/run', { method: 'POST' });
};

connect();
