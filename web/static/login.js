const f = document.getElementById('f'), err = document.getElementById('err');
f.addEventListener('submit', async (e) => {
  e.preventDefault();
  err.textContent = '';
  const res = await fetch('/api/login', { method: 'POST', body: new FormData(f) });
  if (res.ok) { location.href = '/app'; } else { err.textContent = await res.text(); }
});
