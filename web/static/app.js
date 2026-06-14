// Send-a-file form
const sf = document.getElementById('sendf');
const st = document.getElementById('status');
function setStatus(msg, kind) { st.textContent = msg; st.className = 'status' + (kind ? ' ' + kind : ''); }

sf.addEventListener('submit', async (e) => {
  e.preventDefault();
  setStatus('Sending…');
  const res = await fetch('/api/send', { method: 'POST', body: new FormData(sf) });
  if (res.ok) { const j = await res.json(); setStatus(j.ok, 'ok'); sf.reset(); }
  else { setStatus(await res.text(), 'err'); }
});

// API-key creation
const kf = document.getElementById('keyf');
const kr = document.getElementById('keyresult');
const kt = document.getElementById('keytoken');
kf.addEventListener('submit', async (e) => {
  e.preventDefault();
  const res = await fetch('/api/keys', { method: 'POST', body: new FormData(kf) });
  if (res.ok) { const j = await res.json(); kt.textContent = j.token; kr.classList.add('show'); kf.reset(); }
});

// Two-factor authentication
const tfaStatus = document.getElementById('tfa-status');
function tfaMsg(msg, kind) { if (tfaStatus) { tfaStatus.textContent = msg; tfaStatus.className = 'status' + (kind ? ' ' + kind : ''); } }

const tfaSetup = document.getElementById('tfa-setup');
if (tfaSetup) {
  tfaSetup.addEventListener('click', async () => {
    const res = await fetch('/api/2fa/setup', { method: 'POST' });
    if (!res.ok) { tfaMsg(await res.text(), 'err'); return; }
    const j = await res.json();
    document.getElementById('tfa-qr').src = j.qr;
    document.getElementById('tfa-secret').textContent = j.secret;
    document.getElementById('tfa-enroll').classList.remove('hidden');
    tfaSetup.classList.add('hidden');
  });
}

const tfaEnable = document.getElementById('tfa-enable');
if (tfaEnable) {
  tfaEnable.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await fetch('/api/2fa/enable', { method: 'POST', body: new FormData(tfaEnable) });
    if (res.ok) { location.reload(); } else { tfaMsg(await res.text(), 'err'); }
  });
}

const tfaDisable = document.getElementById('tfa-disable');
if (tfaDisable) {
  tfaDisable.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await fetch('/api/2fa/disable', { method: 'POST', body: new FormData(tfaDisable) });
    if (res.ok) { location.reload(); } else { tfaMsg(await res.text(), 'err'); }
  });
}
