# Billing (Stripe) setup

The web service has a `/pricing` page and Stripe Checkout wired in, but billing
is **off until you provide Stripe config**. Without it, `/pricing` shows the
plans and the upgrade button is disabled; everything else works.

No Stripe SDK is used — the service calls the Stripe REST API directly and
verifies webhook signatures with stdlib crypto.

## 1. In the Stripe Dashboard

1. Create a **Product** "KyberCrypt Pro" with a **recurring Price** (e.g.
   $5/month). Copy the **price ID** (`price_...`).
2. Get your **secret key** (`sk_live_...` or `sk_test_...`).
3. Add a **webhook endpoint** → `https://kybercrypt.com/api/billing/webhook`,
   subscribed to **`checkout.session.completed`** and
   **`customer.subscription.deleted`**. Copy its **signing secret** (`whsec_...`).

## 2. Configure the service

Add to `/etc/kyber-web/kyber-web.env` and `systemctl restart kyber-web`:

```
STRIPE_SECRET_KEY=sk_live_xxx
STRIPE_PRICE_ID=price_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx
PRO_PRICE=$5/mo          # display only
```

## How it works

- **Upgrade:** logged-in user clicks Upgrade on `/pricing` →
  `POST /api/billing/checkout` creates a Stripe Checkout Session
  (`client_reference_id` = username) → user is redirected to Stripe → returns to
  `/billing/success`.
- **Activation:** Stripe calls the webhook; on `checkout.session.completed` the
  user's `plan` is set to `pro` (and their Stripe customer/subscription IDs are
  stored). On `customer.subscription.deleted` the plan reverts to `free`.
- Plan limits (file size, retention) are enforced from the `plan` field, so no
  other code changes when a user upgrades/downgrades.

## Notes

- Accounts have no email; Stripe collects it at checkout and the username is
  carried via `client_reference_id`, so payments are attributed correctly.
- Test mode: use `sk_test_...`, a test price, and Stripe's test cards. The Stripe
  CLI can forward webhooks to localhost for development.
