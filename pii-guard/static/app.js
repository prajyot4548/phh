const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let found = [];
let vaultPage = 1, logPage = 1;
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

async function api(url, body) {
  const res = await fetch(url, body ? {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)} : {});
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'Something went wrong. Is the server running?');
  return data;
}
function toast(msg, bad) {
  const t = $('#toast'); t.textContent = msg; t.className = 'toast show' + (bad ? ' bad' : '');
  clearTimeout(t._h); t._h = setTimeout(() => t.className = 'toast', 3600);
}
const tagClass = t => 't-' + t.split(' ')[0];
const fmtSize = b => b > 1048576 ? (b/1048576).toFixed(1)+' MB' : Math.max(1,Math.round(b/1024))+' KB';

/* Tabs */
document.querySelectorAll('.tab').forEach(b => b.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('on', x === b));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('on', p.id === b.dataset.tab));
  if (b.dataset.tab === 'vault') { vaultPage = 1; loadVault(); }
  if (b.dataset.tab === 'log') { logPage = 1; loadLog(); }
  if (b.dataset.tab === 'settings') loadSettings();
});

/* Password dialog -> returns password or null */
function paintMeter(fillEl, labelEl, tipsEl, s) {
  const pct = [6, 20, 40, 60, 80, 100][s.score] ?? 0;
  const colors = ['var(--coral)','var(--coral)','#F5A623','var(--sun)','var(--sky)','var(--mint)'];
  if (fillEl) { fillEl.style.width = pct + '%'; fillEl.style.background = colors[s.score] || colors[0]; }
  if (labelEl) labelEl.textContent = s.label ? `Strength: ${s.label}` : '';
  if (tipsEl) tipsEl.innerHTML = (s.tips || []).map(t => `<li>${esc(t)}</li>`).join('');
}

function askPassword({title, text, confirm}) {
  return new Promise(resolve => {
    $('#mTitle').textContent = title; $('#mText').textContent = text;
    $('#pw2').hidden = !confirm; $('#mWarn').hidden = !confirm; $('#mMeterBox').hidden = !confirm;
    $('#pw').value = $('#pw2').value = '';
    paintMeter($('#mMeterFill'), null, null, {score: 0});
    $('#modal').hidden = false; $('#pw').focus();
    const onInput = () => confirm && api('/api/password-strength', {password: $('#pw').value})
      .then(s => paintMeter($('#mMeterFill'), null, null, s)).catch(() => {});
    $('#pw').addEventListener('input', debounce(onInput, 200));
    const close = v => { $('#modal').hidden = true; $('#pwForm').onsubmit = null; $('#mCancel').onclick = null; resolve(v); };
    $('#mCancel').onclick = () => close(null);
    $('#pwForm').onsubmit = e => {
      e.preventDefault();
      if (confirm && $('#pw').value !== $('#pw2').value) return toast('Passwords do not match.', true);
      close($('#pw').value);
    };
  });
}

/* Scan */
$('#toggleCustom').onclick = () => {
  const box = $('#customBox');
  box.hidden = !box.hidden;
  if (!box.hidden) $('#folder').focus();
};

async function runScan(url, body, btn, busyText) {
  document.querySelectorAll('#systemScanBtn, #scanBtn').forEach(b => b.disabled = true);
  $('#progressText').textContent = busyText;
  $('#progress').hidden = false; $('#results').hidden = true;
  try {
    const d = await api(url, body);
    found = d.results; renderResults(d);
  } catch (e) { toast(e.message, true); }
  document.querySelectorAll('#systemScanBtn, #scanBtn').forEach(b => b.disabled = false);
  $('#progress').hidden = true;
}

$('#systemScanBtn').onclick = () => runScan('/api/scan-system', {}, '#systemScanBtn',
  'Checking Desktop, Documents, Downloads, Pictures and other drives…');

$('#scanBtn').onclick = () => {
  const folder = $('#folder').value.trim();
  if (!folder) return toast('Enter a folder path first.', true);
  runScan('/api/scan', {folder}, '#scanBtn', 'Reading files… large folders can take a minute.');
};
$('#folder').addEventListener('keydown', e => e.key === 'Enter' && $('#scanBtn').click());

function renderResults(d) {
  $('#results').hidden = false;
  $('#summary').innerHTML =
    `<div class="stat s1"><b>${d.scanned}</b><span>files read</span></div>
     <div class="stat s2"><b>${d.results.length}</b><span>with personal ID</span></div>
     <div class="stat s3"><b>${d.skipped}</b><span>skipped (too big or unreadable)</span></div>` +
    (d.folders && d.folders.length > 1 ? `<div class="folders">Checked: ${d.folders.map(f => esc(f)).join(' · ')}</div>` : '');
  $('.toolbar').hidden = !d.results.length;
  $('#list').innerHTML = d.results.length ? d.results.map((r, i) => `
    <li class="item">
      <input type="checkbox" class="pick" data-i="${i}" checked aria-label="Select ${esc(r.name)}">
      <div class="body"><div class="name">${esc(r.name)} <span class="when">${fmtSize(r.size)}</span>
          <span class="risk risk-${r.risk}">${esc(r.risk)} risk</span></div>
        <div class="path">${esc(r.path)}</div>
        <div class="tags">${Object.entries(r.found).map(([k, v]) =>
          `<span class="tag ${tagClass(k)}">${esc(k)}<i>${esc(v.join(', '))}</i></span>`).join('')}</div>
      </div></li>`).join('')
    : `<li class="empty"><b>This folder looks clean.</b><br>No PAN, Aadhaar, Voter ID, bank, card or other personal numbers found.</li>`;
  $('#selAll').checked = true;
}
$('#selAll').onchange = e => document.querySelectorAll('.pick').forEach(c => c.checked = e.target.checked);

/* Lock */
$('#lockBtn').onclick = async () => {
  const files = [...document.querySelectorAll('.pick:checked')].map(c => {
    const r = found[+c.dataset.i]; return {path: r.path, types: Object.keys(r.found)};
  });
  if (!files.length) return toast('Select at least one file.', true);
  const password = await askPassword({title: 'Set a password', confirm: true,
    text: `${files.length} file(s) will be locked. You'll need this password to open them again.`});
  if (!password) return;
  $('#lockBtn').disabled = true;
  try {
    const d = await api('/api/encrypt', {files, password});
    toast(`Locked ${d.encrypted} file(s)` + (d.failed.length ? `, ${d.failed.length} failed.` : '.'), d.failed.length > 0);
    found = found.filter(r => !files.some(f => f.path === r.path && !d.failed.some(x => x.path === f.path)));
    renderResults({scanned: 0, skipped: 0, results: found}); $('#summary').innerHTML = '';
    refreshCount();
  } catch (e) { toast(e.message, true); }
  $('#lockBtn').disabled = false;
};

/* Vault */
function renderPager(el, page, total, pageSize, onGo) {
  if (total <= pageSize) { el.innerHTML = ''; return; }
  const pages = Math.ceil(total / pageSize);
  el.innerHTML = `<button ${page<=1?'disabled':''} data-go="${page-1}">Previous</button>
    <span>Page ${page} of ${pages}</span>
    <button ${page>=pages?'disabled':''} data-go="${page+1}">Next</button>`;
  el.querySelectorAll('button').forEach(b => b.onclick = () => onGo(+b.dataset.go));
}

async function loadVault() {
  const status = $('#vaultFilter').value;
  const q = $('#vaultSearch').value.trim();
  const params = new URLSearchParams({page: vaultPage});
  if (status) params.set('status', status);
  if (q) params.set('q', q);
  try {
    const d = await api('/api/vault?' + params.toString());
    const rows = d.rows;
    $('#vaultList').innerHTML = rows.length ? rows.map(r => `
      <li class="item">
        <div class="body"><div class="name">${esc(r.original_path.split(/[\\/]/).pop())}
            ${r.risk_level ? `<span class="risk risk-${r.risk_level}">${esc(r.risk_level)} risk</span>` : ''}</div>
          <div class="path">${esc(r.original_path)}</div>
          <div class="tags">${(r.pii_types||'').split(', ').filter(Boolean).map(t => `<span class="tag ${tagClass(t)}">${esc(t)}</span>`).join('')}</div></div>
        <div style="text-align:right"><span class="badge b-${r.status}">${r.status === 'ENCRYPTED' ? 'Locked' : 'Unlocked'}</span>
          <div class="when">${esc(r.restored_at || r.created_at)}</div></div>
        ${r.status === 'ENCRYPTED'
          ? `<button class="btn primary small" data-id="${r.id}">Unlock</button>`
          : `<button class="btn ghost small" data-del="${r.id}">Remove</button>`}
      </li>`).join('')
      : `<li class="empty"><b>Nothing here.</b><br>${q || status ? 'Try a different search or filter.' : 'Scan a folder to find files that need protection.'}</li>`;
    document.querySelectorAll('#vaultList [data-id]').forEach(b => b.onclick = () => unlock(+b.dataset.id));
    document.querySelectorAll('#vaultList [data-del]').forEach(b => b.onclick = () => removeRecord(+b.dataset.del));
    renderPager($('#vaultPager'), d.page, d.total, d.page_size, p => { vaultPage = p; loadVault(); });
  } catch (e) { toast(e.message, true); }
}
$('#vaultFilter').onchange = () => { vaultPage = 1; loadVault(); };
$('#vaultSearch').addEventListener('input', debounce(() => { vaultPage = 1; loadVault(); }, 300));

async function unlock(id) {
  const password = await askPassword({title: 'Enter your password', text: 'This unlocks the file and puts it back where it was.', confirm: false});
  if (!password) return;
  try { await api('/api/decrypt', {id, password}); toast('File unlocked and restored.'); loadVault(); refreshCount(); }
  catch (e) { toast(e.message, true); }
}
async function removeRecord(id) {
  try { await fetch('/api/vault/' + id, {method: 'DELETE'}); toast('Removed from the list.'); loadVault(); }
  catch { toast('Could not remove that record.', true); }
}

async function loadLog() {
  try {
    const rows = await api('/api/logs?page=' + logPage);
    $('#logList').innerHTML = rows.length ? rows.map(r => `
      <li class="item"><span class="badge b-${r.action === 'DECRYPT_FAILED' ? 'RESTORED' : 'ENCRYPTED'}">${esc(r.action.replace('_',' ').toLowerCase())}</span>
      <div class="body path">${esc(r.detail || '')}</div><span class="when">${esc(r.created_at)}</span></li>`).join('')
      : `<li class="empty">No activity yet.</li>`;
    $('#logPager').innerHTML = `<button ${logPage<=1?'disabled':''} data-go="${logPage-1}">Previous</button>
      <span>Page ${logPage}</span>
      <button ${rows.length<100?'disabled':''} data-go="${logPage+1}">Next</button>`;
    $('#logPager').querySelectorAll('button').forEach(b => b.onclick = () => { logPage = +b.dataset.go; loadLog(); });
  } catch (e) { toast(e.message, true); }
}

/* Settings */
async function loadSettings() {
  try {
    const [s, breakdown] = await Promise.all([api('/api/settings'), api('/api/pii-breakdown')]);
    $('#folderPreview').innerHTML = s.scan_folders_preview.length
      ? s.scan_folders_preview.map(f => `<li>${esc(f)}</li>`).join('')
      : '<li>No personal folders found on this PC.</li>';
    const max = Math.max(1, ...Object.values(breakdown));
    const entries = Object.entries(breakdown);
    $('#breakdown').innerHTML = entries.length ? entries.map(([k, v]) => `
      <div class="bar-row"><span>${esc(k)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${(v/max)*100}%"></div></div>
        <span>${v}</span></div>`).join('')
      : '<p class="sub">Nothing locked yet — scan and lock some files first.</p>';
  } catch (e) { toast(e.message, true); }
}
$('#tryPw').addEventListener('input', debounce(async e => {
  const s = await api('/api/password-strength', {password: e.target.value}).catch(() => ({score:0,label:'',tips:[]}));
  paintMeter($('#meterFill'), $('#meterLabel'), $('#meterTips'), s);
}, 150));
$('#suggestBtn').onclick = async () => {
  const d = await api('/api/suggest-password').catch(() => null);
  if (!d) return;
  $('#tryPw').type = 'text'; $('#tryPw').value = d.password;
  const s = await api('/api/password-strength', {password: d.password});
  paintMeter($('#meterFill'), $('#meterLabel'), $('#meterTips'), s);
  toast('Suggested password filled in — copy it before you close this tab.');
};

async function refreshCount() {
  try { $('#vaultCount').textContent = (await api('/api/stats')).encrypted; } catch {}
}
refreshCount();
