const up = document.getElementById('upgrade');
if (up) {
  up.addEventListener('click', async () => {
    up.disabled = true;
    const err = document.getElementById('err');
    if (err) err.textContent = '';
    const res = await fetch('/api/billing/checkout', { method: 'POST' });
    if (res.ok) {
      const j = await res.json();
      location.href = j.url; // redirect to Stripe Checkout
    } else {
      up.disabled = false;
      const j = await res.json().catch(() => ({}));
      if (err) err.textContent = j.error || 'Could not start checkout.';
    }
  });
}
