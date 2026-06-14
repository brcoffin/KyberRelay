const f = document.getElementById('f');
const err = document.getElementById('err');
const btn = document.getElementById('loginbtn');
let pending = null; // set once password is accepted and 2FA is required

f.addEventListener('submit', async (e) => {
  e.preventDefault();
  err.textContent = '';

  if (pending) {
    // Second step: verify the authenticator code.
    const fd = new FormData();
    fd.set('pending', pending);
    fd.set('code', document.getElementById('code').value);
    const res = await fetch('/api/login/totp', { method: 'POST', body: fd });
    if (res.ok) { location.href = '/app'; } else { err.textContent = await res.text(); }
    return;
  }

  const res = await fetch('/api/login', { method: 'POST', body: new FormData(f) });
  if (!res.ok) { err.textContent = await res.text(); return; }
  const j = await res.json().catch(() => ({}));
  if (j.totp_required) {
    pending = j.pending;
    document.getElementById('creds').classList.add('hidden');
    document.getElementById('totpstep').classList.remove('hidden');
    btn.textContent = 'Verify';
    document.getElementById('code').focus();
  } else {
    location.href = '/app';
  }
});
