// Per-session CSRF token (from the page meta tag), sent on every state-changing
// fetch as the X-CSRF-Token header. HTML form posts carry it as a hidden field.
const CSRF = document.querySelector('meta[name="csrf-token"]')?.content || '';
const csrfHeaders = { 'X-CSRF-Token': CSRF };

// Send-a-file form
const sf = document.getElementById('sendf');
const st = document.getElementById('status');
function setStatus(msg, kind) { st.textContent = msg; st.className = 'status' + (kind ? ' ' + kind : ''); }

sf.addEventListener('submit', async (e) => {
  e.preventDefault();
  setStatus('Sending…');
  const res = await fetch('/api/send', { method: 'POST', headers: csrfHeaders, body: new FormData(sf) });
  if (res.ok) { const j = await res.json(); setStatus(j.ok, 'ok'); sf.reset(); }
  else { setStatus(await res.text(), 'err'); }
});

// API-key creation
const kf = document.getElementById('keyf');
const kr = document.getElementById('keyresult');
const kt = document.getElementById('keytoken');
kf.addEventListener('submit', async (e) => {
  e.preventDefault();
  const res = await fetch('/api/keys', { method: 'POST', headers: csrfHeaders, body: new FormData(kf) });
  if (res.ok) { const j = await res.json(); kt.textContent = j.token; kr.classList.add('show'); kf.reset(); }
});

// Two-factor authentication
const tfaStatus = document.getElementById('tfa-status');
function tfaMsg(msg, kind) { if (tfaStatus) { tfaStatus.textContent = msg; tfaStatus.className = 'status' + (kind ? ' ' + kind : ''); } }

const tfaSetup = document.getElementById('tfa-setup');
if (tfaSetup) {
  tfaSetup.addEventListener('click', async () => {
    const res = await fetch('/api/2fa/setup', { method: 'POST', headers: csrfHeaders });
    if (!res.ok) { tfaMsg(await res.text(), 'err'); return; }
    const j = await res.json();
    document.getElementById('tfa-qr').src = j.qr;
    document.getElementById('tfa-secret').textContent = j.secret;
    document.getElementById('tfa-enroll').classList.remove('hidden');
    tfaSetup.classList.add('hidden');
  });
}

function showRecoveryCodes(codes) {
  const list = document.getElementById('tfa-code-list');
  list.innerHTML = '';
  (codes || []).forEach((c) => { const li = document.createElement('li'); li.textContent = c; list.appendChild(li); });
  const enroll = document.getElementById('tfa-enroll'); if (enroll) enroll.classList.add('hidden');
  document.getElementById('tfa-codes').classList.remove('hidden');
}

const tfaEnable = document.getElementById('tfa-enable');
if (tfaEnable) {
  tfaEnable.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await fetch('/api/2fa/enable', { method: 'POST', headers: csrfHeaders, body: new FormData(tfaEnable) });
    if (res.ok) { const j = await res.json(); showRecoveryCodes(j.recovery_codes); }
    else { tfaMsg(await res.text(), 'err'); }
  });
}

const tfaRegen = document.getElementById('tfa-regen');
if (tfaRegen) {
  tfaRegen.addEventListener('click', async () => {
    const res = await fetch('/api/2fa/recovery', { method: 'POST', headers: csrfHeaders });
    if (res.ok) { const j = await res.json(); showRecoveryCodes(j.recovery_codes); }
    else { tfaMsg(await res.text(), 'err'); }
  });
}

const tfaDone = document.getElementById('tfa-done');
if (tfaDone) { tfaDone.addEventListener('click', () => location.reload()); }

// Change password
const pwform = document.getElementById('pwform');
if (pwform) {
  const pwStatus = document.getElementById('pw-status');
  pwform.addEventListener('submit', async (e) => {
    e.preventDefault();
    pwStatus.textContent = 'Updating…'; pwStatus.className = 'status';
    const res = await fetch('/api/account/password', { method: 'POST', headers: csrfHeaders, body: new FormData(pwform) });
    if (res.ok) { pwStatus.textContent = 'Password changed.'; pwStatus.className = 'status ok'; pwform.reset(); }
    else { pwStatus.textContent = await res.text(); pwStatus.className = 'status err'; }
  });
}

const tfaDisable = document.getElementById('tfa-disable');
if (tfaDisable) {
  tfaDisable.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await fetch('/api/2fa/disable', { method: 'POST', headers: csrfHeaders, body: new FormData(tfaDisable) });
    if (res.ok) { location.reload(); } else { tfaMsg(await res.text(), 'err'); }
  });
}
