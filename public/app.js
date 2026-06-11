// app.js — frontend logic for the container-image management UI.

const state = {
  images: [],
  selected: new Set(),
  caps: { engine: '', canExport: false, canImport: false },
  openMenuKey: null,
  /** Map<imageId, {status, reason?}> — populated asynchronously after render. */
  signatures: new Map(),
};

const el = {
  body: document.getElementById('imagesBody'),
  selectAll: document.getElementById('selectAll'),
  refreshBtn: document.getElementById('refreshBtn'),
  uploadInput: document.getElementById('uploadInput'),
  uploadLabel: document.getElementById('uploadLabel'),
  bulkBar: document.getElementById('bulkBar'),
  bulkCount: document.getElementById('bulkCount'),
  bulkDownloadBtn: document.getElementById('bulkDownloadBtn'),
  bulkDeleteBtn: document.getElementById('bulkDeleteBtn'),
  engineBadge: document.getElementById('engineBadge'),
  dropzone: document.getElementById('dropzone'),
  detailsModal: document.getElementById('detailsModal'),
  detailsBody: document.getElementById('detailsBody'),
  detailsClose: document.getElementById('detailsClose'),
  pullBtn: document.getElementById('pullBtn'),
  pullModal: document.getElementById('pullModal'),
  pullDialog: document.getElementById('pullDialog'),
  pullForm: document.getElementById('pullForm'),
  pullInput: document.getElementById('pullInput'),
  pullClose: document.getElementById('pullClose'),
  pullCancel: document.getElementById('pullCancel'),
  pullSubmit: document.getElementById('pullSubmit'),
  toast: document.getElementById('toast'),
  progressModal: document.getElementById('progressModal'),
  progressTitle: document.getElementById('progressTitle'),
  progressOutput: document.getElementById('progressOutput'),
  progressClose: document.getElementById('progressClose'),
};

// A stable per-row key (repo:tag pair is not always unique, so combine with id).
function rowKey(img) {
  return `${img.id}|${img.repo}|${img.tag}`;
}

// The CLI reference used for operations.
function rowRef(img) {
  if (img.repo && img.repo !== '<none>' && img.tag && img.tag !== '<none>') {
    return `${img.repo}:${img.tag}`;
  }
  return img.id;
}

function formatSize(bytes) {
  if (!bytes || bytes <= 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let i = 0;
  while (value >= 1000 && i < units.length - 1) {
    value /= 1000;
    i++;
  }
  return `${value.toFixed(value >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function shortId(id) {
  const clean = id.startsWith('sha256:') ? id.slice(7) : id;
  return clean.slice(0, 12);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]),
  );
}

let toastTimer;
function showToast(message, isError = false) {
  el.toast.textContent = message;
  el.toast.classList.toggle('error', isError);
  el.toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.toast.hidden = true;
  }, 4000);
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

async function api(path, options) {
  const res = await fetch(path, options);
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('application/json') ? await res.json() : null;
  if (!res.ok) {
    throw new Error((data && data.error) || `Request failed (${res.status})`);
  }
  return data;
}

async function loadCapabilities() {
  state.caps = await api('/api/capabilities');
  el.engineBadge.textContent = state.caps.engine;
  el.engineBadge.hidden = false;
  if (!state.caps.canImport) {
    el.uploadLabel.classList.add('btn');
    el.uploadInput.disabled = true;
    el.uploadLabel.setAttribute('title', 'Upload not supported in this environment');
    el.uploadLabel.style.opacity = '0.5';
    el.uploadLabel.style.pointerEvents = 'none';
  }
}

async function loadImages() {
  el.body.innerHTML = '<tr class="empty-row"><td colspan="5">Loading…</td></tr>';
  try {
    const data = await api('/api/images');
    state.images = data.images || [];
    // Drop selections that no longer exist.
    const keys = new Set(state.images.map(rowKey));
    for (const k of [...state.selected]) if (!keys.has(k)) state.selected.delete(k);
    render();
  } catch (err) {
    el.body.innerHTML = `<tr class="empty-row"><td colspan="5">${escapeHtml(err.message)}</td></tr>`;
  }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

function render() {
  if (state.images.length === 0) {
    el.body.innerHTML = '<tr class="empty-row"><td colspan="5">No images found.</td></tr>';
  } else {
    el.body.innerHTML = state.images.map(rowHtml).join('');
  }
  updateBulkBar();
  syncSelectAll();
  // Kick off async signature verification for all unique image ids.
  verifyAllImages();
}

function rowHtml(img) {
  const key = rowKey(img);
  const selected = state.selected.has(key);
  const repo = img.repo === '<none>' ? '<span class="muted">&lt;none&gt;</span>' : escapeHtml(img.repo);
  const tag =
    img.tag === '<none>'
      ? '<span class="muted">&lt;none&gt;</span>'
      : `<span class="tag-pill">${escapeHtml(img.tag)}</span>`;
  const sigInfo = state.signatures.get(img.id);
  const sigIcon = renderSigIcon(sigInfo);
  const dlDisabled = state.caps.canExport ? '' : 'disabled';
  return `
    <tr class="${selected ? 'selected' : ''}" data-key="${escapeHtml(key)}" data-img-id="${escapeHtml(img.id)}">
      <td class="col-check"><input type="checkbox" class="row-check" ${selected ? 'checked' : ''} /></td>
      <td><span class="image-name">${repo}</span>${sigIcon}</td>
      <td>${tag}</td>
      <td>${formatSize(img.size)}</td>
      <td class="actions-cell">
        <button class="actions-btn" aria-label="Actions" data-action="menu">&#8943;</button>
        <div class="menu" hidden>
          <button data-action="details">Details</button>
          <button data-action="download" ${dlDisabled}>Download</button>
          <button data-action="delete" class="danger">Delete</button>
        </div>
      </td>
    </tr>`;
}

function imageByKey(key) {
  return state.images.find((img) => rowKey(img) === key);
}

// ---------------------------------------------------------------------------
// Signature helpers
// ---------------------------------------------------------------------------

/**
 * Return an HTML string for the signature status dot.
 * sigInfo is undefined while loading, or {status, reason?} once resolved.
 */
function renderSigIcon(sigInfo) {
  if (!sigInfo) {
    return '<span class="sig-icon sig-unknown" title="Checking signature…"></span>';
  }
  const { status, reason } = sigInfo;
  if (status === 'unsigned') {
    return '<span class="sig-icon sig-unsigned" title="No signature"></span>';
  }
  if (status === 'valid') {
    return '<span class="sig-icon sig-valid" title="Signature valid"></span>';
  }
  const tooltip = reason ? `Signature invalid: ${reason}` : 'Signature invalid';
  return `<span class="sig-icon sig-invalid" title="${escapeHtml(tooltip)}"></span>`;
}

/**
 * Update the signature icon for images whose id is in the given statuses map.
 * Called after the verify API responds; avoids a full re-render.
 */
function patchSigIcons(statuses) {
  for (const [id, sigInfo] of Object.entries(statuses)) {
    state.signatures.set(id, sigInfo);
    // Update every row that has this image id (multiple tags share the same id).
    for (const tr of el.body.querySelectorAll(`tr[data-img-id="${CSS.escape(id)}"]`)) {
      const icon = tr.querySelector('.sig-icon');
      if (icon) icon.outerHTML = renderSigIcon(sigInfo);
    }
  }
}

/** Collect unique ids from current image list and verify them in one batch. */
async function verifyAllImages() {
  if (state.images.length === 0) return;
  const ids = [...new Set(state.images.map((img) => img.id))];
  try {
    const data = await api('/api/images/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids }),
    });
    patchSigIcons(data.statuses || {});
  } catch {
    // Silently ignore — icons remain in the "unknown" (grey) state.
  }
}

function updateBulkBar() {
  const n = state.selected.size;
  el.bulkBar.hidden = n === 0;
  el.bulkCount.textContent = `${n} selected`;
  el.bulkDownloadBtn.disabled = !state.caps.canExport;
}

function syncSelectAll() {
  const total = state.images.length;
  const sel = state.selected.size;
  el.selectAll.checked = total > 0 && sel === total;
  el.selectAll.indeterminate = sel > 0 && sel < total;
}

// ---------------------------------------------------------------------------
// Menu handling
// ---------------------------------------------------------------------------

function closeMenus() {
  for (const m of el.body.querySelectorAll('.menu')) m.hidden = true;
  state.openMenuKey = null;
}

document.addEventListener('click', (e) => {
  if (!e.target.closest('.actions-cell')) closeMenus();
});

// ---------------------------------------------------------------------------
// Progress modal (SSE streaming)
// ---------------------------------------------------------------------------

/**
 * Open the progress modal and connect to an SSE endpoint.
 * Returns a promise that resolves with the `done` event payload ({ ok, code })
 * once the server closes the stream.
 *
 * For POST requests (upload), pass fetchOpts with method/body. In that case we
 * use fetch + ReadableStream to parse the SSE-formatted response instead of
 * EventSource (which only supports GET).
 */
function openProgress(title, url, { fetchOpts } = {}) {
  el.progressTitle.textContent = title;
  el.progressOutput.textContent = '';
  el.progressClose.disabled = true;
  el.progressModal.hidden = false;

  return fetchOpts ? openProgressFetch(url, fetchOpts) : openProgressSSE(url);
}

function appendProgress(text) {
  const span = document.createElement('span');
  if (text.startsWith('$ ')) {
    span.className = 'cmd-line';
  }
  span.textContent = text + '\n';
  el.progressOutput.appendChild(span);
  el.progressOutput.scrollTop = el.progressOutput.scrollHeight;
}

function finishProgress(ok) {
  const span = document.createElement('span');
  span.className = ok ? 'success-line' : 'error-line';
  span.textContent = ok ? '\nDone.' : '\nFailed.';
  el.progressOutput.appendChild(span);
  el.progressOutput.scrollTop = el.progressOutput.scrollHeight;
  el.progressClose.disabled = false;
}

/** EventSource-based (GET endpoints). */
function openProgressSSE(url) {
  return new Promise((resolve) => {
    const es = new EventSource(url);
    es.onmessage = (e) => appendProgress(e.data);
    es.addEventListener('done', (e) => {
      es.close();
      let payload;
      try { payload = JSON.parse(e.data); } catch { payload = { ok: false }; }
      finishProgress(payload.ok);
      resolve(payload);
    });
    es.onerror = () => {
      es.close();
      finishProgress(false);
      resolve({ ok: false, code: -1 });
    };
  });
}

/** Fetch-based SSE parsing (POST endpoints like upload). */
function openProgressFetch(url, fetchOpts) {
  return new Promise(async (resolve) => {
    try {
      const res = await fetch(url, fetchOpts);
      if (!res.ok || !res.body) {
        appendProgress(`Request failed (${res.status})`);
        finishProgress(false);
        resolve({ ok: false, code: -1 });
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      let lastPayload = { ok: false, code: -1 };

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        // Parse SSE frames (lines separated by double newlines).
        const frames = buf.split('\n\n');
        buf = frames.pop(); // keep incomplete frame
        for (const frame of frames) {
          if (!frame.trim()) continue;
          let eventType = 'message';
          const dataLines = [];
          for (const line of frame.split('\n')) {
            if (line.startsWith('event: ')) eventType = line.slice(7);
            else if (line.startsWith('data: ')) dataLines.push(line.slice(6));
          }
          const data = dataLines.join('\n');
          if (eventType === 'done') {
            try { lastPayload = JSON.parse(data); } catch { /* keep default */ }
            finishProgress(lastPayload.ok);
            resolve(lastPayload);
            return;
          }
          if (data) appendProgress(data);
        }
      }
      // Stream ended without a `done` event.
      finishProgress(false);
      resolve(lastPayload);
    } catch (err) {
      appendProgress(`Error: ${err.message}`);
      finishProgress(false);
      resolve({ ok: false, code: -1 });
    }
  });
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

async function deleteRefs(refs) {
  if (refs.length === 0) return;
  const label = refs.length === 1 ? refs[0] : `${refs.length} images`;
  if (!confirm(`Delete ${label}? This cannot be undone.`)) return;

  const idsParam = refs.map(encodeURIComponent).join(',');
  await openProgress('Deleting images', `/api/stream/delete?ids=${idsParam}`);

  state.selected.clear();
  await loadImages();
}

async function downloadRefs(refs) {
  if (refs.length === 0) return;
  if (!state.caps.canExport) {
    showToast('Download not supported in this environment', true);
    return;
  }
  const title = refs.length === 1 ? `Downloading ${refs[0]}` : `Downloading ${refs.length} images`;
  const idsParam = refs.map(encodeURIComponent).join(',');
  const result = await openProgress(title, `/api/stream/download?ids=${idsParam}`);
  if (result.ok && result.token) {
    triggerUrlDownload(`/api/download?token=${encodeURIComponent(result.token)}`);
  }
}

function triggerUrlDownload(url) {
  const a = document.createElement('a');
  a.href = url;
  a.download = '';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

async function showDetails(img) {
  el.detailsBody.innerHTML = '<p class="muted">Loading…</p>';
  el.detailsModal.hidden = false;
  try {
    const data = await api(`/api/images/${encodeURIComponent(rowRef(img))}`);
    const d = data.details || {};
    const sig = data.signature;
    el.detailsBody.innerHTML = `
      <div class="detail-row"><span class="detail-label">Image</span><span class="detail-value">${escapeHtml(
        img.repo,
      )}</span></div>
      <div class="detail-row"><span class="detail-label">Tag</span><span class="detail-value">${escapeHtml(
        img.tag,
      )}</span></div>
      <div class="detail-row"><span class="detail-label">ID</span><span class="detail-value">${escapeHtml(
        data.id,
      )}</span></div>
      <div class="detail-row"><span class="detail-label">Size</span><span class="detail-value">${formatSize(
        img.size,
      )}</span></div>
      <div class="detail-row"><span class="detail-label">OS</span><span class="detail-value">${valueOrNotFound(
        d.os,
      )}</span></div>
      <div class="detail-row"><span class="detail-label">Arch</span><span class="detail-value">${valueOrNotFound(
        d.architecture,
      )}</span></div>
      <div class="detail-row"><span class="detail-label">Signature</span><span class="detail-value">${renderSigDetail(
        sig,
      )}</span></div>
      <div class="detail-sections">
        ${section('Labels', renderLabels(d.labels))}
        ${section('Layers', renderList(d.layers))}
        ${section('Entrypoint', renderList(d.entrypoint))}
        ${section('Cmd', renderList(d.cmd))}
        ${section('Env', renderList(d.env))}
        ${section('ExposedPorts', renderList(d.exposedPorts))}
      </div>`;
  } catch (err) {
    el.detailsBody.innerHTML = `<p class="muted">${escapeHtml(err.message)}</p>`;
  }
}

function valueOrNotFound(value) {
  return value ? escapeHtml(value) : '<span class="muted">not found</span>';
}

/** Render the signature status for the details modal. */
function renderSigDetail(sig) {
  if (!sig) return '<span class="muted">unknown</span>';
  const { status, reason } = sig;
  if (status === 'unsigned') {
    return '<span class="sig-badge">Not signed</span>';
  }
  if (status === 'valid') {
    return '<span class="sig-badge">&#10003; Valid</span>';
  }
  const reasonHtml = reason
    ? `<span class="sig-reason">${escapeHtml(reason)}</span>`
    : '';
  return `<span class="sig-badge">&#10007; Invalid</span>${reasonHtml}`;
}

// Build a collapsible <details> section; renders "not found" when body is empty.
function section(title, bodyHtml) {
  const content = bodyHtml || '<span class="muted">not found</span>';
  return `
    <details class="detail-section">
      <summary>${escapeHtml(title)}</summary>
      <div class="detail-section-body">${content}</div>
    </details>`;
}

// Render an array of strings as a monospace list, or empty (-> "not found").
function renderList(items) {
  if (!Array.isArray(items) || items.length === 0) return '';
  return `<ul class="detail-ul">${items
    .map((v) => `<li>${escapeHtml(v)}</li>`)
    .join('')}</ul>`;
}

// Render a labels object as key/value rows, or empty (-> "not found").
function renderLabels(labels) {
  if (!labels || typeof labels !== 'object') return '';
  const keys = Object.keys(labels);
  if (keys.length === 0) return '';
  return `<dl class="detail-dl">${keys
    .map(
      (k) =>
        `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(labels[k])}</dd>`,
    )
    .join('')}</dl>`;
}

async function uploadFile(file) {
  if (!file) return;
  const name = file.name.toLowerCase();
  const ok = name.endsWith('.tar') || name.endsWith('.tar.gz') || name.endsWith('.tgz') || name.endsWith('.tar.xz');
  if (!ok) {
    showToast('Unsupported file type. Use .tar, .tar.gz/.tgz, or .tar.xz', true);
    return;
  }
  const result = await openProgress(`Importing ${file.name}`, `/api/stream/upload?filename=${encodeURIComponent(file.name)}`, {
    fetchOpts: {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: file,
    },
  });
  if (result.ok) await loadImages();
}

function openPullModal() {
  const r = el.pullBtn.getBoundingClientRect();
  el.pullDialog.style.top  = `${r.bottom + 6}px`;
  el.pullDialog.style.left = `${r.left}px`;
  el.pullInput.value = '';
  el.pullModal.hidden = false;
  el.pullInput.focus();
}

function closePullModal() {
  el.pullModal.hidden = true;
}

async function submitPull() {
  const ref = el.pullInput.value.trim();
  if (!ref) {
    el.pullInput.focus();
    return;
  }
  closePullModal();
  const result = await openProgress(`Pulling ${ref}`, `/api/stream/pull?ref=${encodeURIComponent(ref)}`);
  if (result.ok) await loadImages();
}

// ---------------------------------------------------------------------------
// Event wiring
// ---------------------------------------------------------------------------

el.body.addEventListener('change', (e) => {
  const check = e.target.closest('.row-check');
  if (!check) return;
  const tr = check.closest('tr');
  const key = tr.dataset.key;
  if (check.checked) state.selected.add(key);
  else state.selected.delete(key);
  tr.classList.toggle('selected', check.checked);
  updateBulkBar();
  syncSelectAll();
});

el.body.addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-action]');
  if (!btn) return;
  const tr = btn.closest('tr');
  const key = tr.dataset.key;
  const img = imageByKey(key);
  const action = btn.dataset.action;

  if (action === 'menu') {
    const menu = tr.querySelector('.menu');
    const willOpen = menu.hidden;
    closeMenus();
    menu.hidden = !willOpen;
    state.openMenuKey = willOpen ? key : null;
    return;
  }

  closeMenus();
  if (!img) return;
  if (action === 'details') showDetails(img);
  else if (action === 'download') downloadRefs([rowRef(img)]);
  else if (action === 'delete') deleteRefs([rowRef(img)]);
});

el.selectAll.addEventListener('change', () => {
  if (el.selectAll.checked) {
    for (const img of state.images) state.selected.add(rowKey(img));
  } else {
    state.selected.clear();
  }
  render();
});

el.refreshBtn.addEventListener('click', loadImages);

el.bulkDeleteBtn.addEventListener('click', () => {
  const refs = selectedRefs();
  deleteRefs(refs);
});

el.bulkDownloadBtn.addEventListener('click', () => {
  const refs = selectedRefs();
  downloadRefs(refs);
});

function selectedRefs() {
  const refs = [];
  for (const img of state.images) {
    if (state.selected.has(rowKey(img))) refs.push(rowRef(img));
  }
  return refs;
}

el.uploadInput.addEventListener('change', () => {
  const file = el.uploadInput.files[0];
  el.uploadInput.value = '';
  uploadFile(file);
});

el.detailsClose.addEventListener('click', () => (el.detailsModal.hidden = true));
el.detailsModal.addEventListener('click', (e) => {
  if (e.target === el.detailsModal) el.detailsModal.hidden = true;
});

el.pullBtn.addEventListener('click', openPullModal);
el.pullClose.addEventListener('click', closePullModal);
el.pullCancel.addEventListener('click', closePullModal);
el.pullModal.addEventListener('click', (e) => {
  if (e.target === el.pullModal) closePullModal();
});
el.pullForm.addEventListener('submit', (e) => {
  e.preventDefault();
  submitPull();
});

el.progressClose.addEventListener('click', () => (el.progressModal.hidden = true));
el.progressModal.addEventListener('click', (e) => {
  if (e.target === el.progressModal && !el.progressClose.disabled) el.progressModal.hidden = true;
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    el.detailsModal.hidden = true;
    el.pullModal.hidden = true;
    if (!el.progressClose.disabled) el.progressModal.hidden = true;
    closeMenus();
  }
});

// Drag & drop upload
let dragDepth = 0;
window.addEventListener('dragenter', (e) => {
  if (!state.caps.canImport) return;
  e.preventDefault();
  dragDepth++;
  el.dropzone.hidden = false;
  el.dropzone.classList.add('dragover');
});
window.addEventListener('dragover', (e) => {
  if (state.caps.canImport) e.preventDefault();
});
window.addEventListener('dragleave', (e) => {
  if (!state.caps.canImport) return;
  e.preventDefault();
  dragDepth = Math.max(0, dragDepth - 1);
  if (dragDepth === 0) {
    el.dropzone.classList.remove('dragover');
    el.dropzone.hidden = true;
  }
});
window.addEventListener('drop', (e) => {
  if (!state.caps.canImport) return;
  e.preventDefault();
  dragDepth = 0;
  el.dropzone.classList.remove('dragover');
  el.dropzone.hidden = true;
  const file = e.dataTransfer.files[0];
  uploadFile(file);
});

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

(async function init() {
  try {
    await loadCapabilities();
  } catch (err) {
    showToast(err.message, true);
  }
  await loadImages();
})();
