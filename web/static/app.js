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
