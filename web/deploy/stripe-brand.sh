#!/usr/bin/env bash
# Re-brand a Stripe account's customer-facing name to KyberCrypt via the API.
#
# Sets, where the API permits: the account's public business name, statement
# descriptor (what shows on bank/card statements), and brand primary color; plus
# the subscription Product's name + statement descriptor. The Checkout/email LOGO
# is a file upload and must be done in the Dashboard (Settings → Branding).
#
# SAFE BY DEFAULT: this is a DRY RUN unless you pass APPLY=1. It reads the secret
# key from $STRIPE_SECRET_KEY and never prints or stores it.
#
# Usage:
#   STRIPE_SECRET_KEY=sk_live_xxx STRIPE_PRICE_ID=price_xxx ./stripe-brand.sh        # preview
#   STRIPE_SECRET_KEY=sk_live_xxx STRIPE_PRICE_ID=price_xxx APPLY=1 ./stripe-brand.sh # write
#
# Tip: run against a test key first (sk_test_...).
set -euo pipefail

: "${STRIPE_SECRET_KEY:?set STRIPE_SECRET_KEY (sk_test_... or sk_live_...)}"
BRAND_NAME="${BRAND_NAME:-KyberCrypt}"
PRODUCT_NAME="${PRODUCT_NAME:-$BRAND_NAME Pro}"
DESCRIPTOR="${DESCRIPTOR:-KYBERCRYPT}" # 5-22 chars, letters/numbers/spaces, must contain a letter
BRAND_COLOR="${BRAND_COLOR:-#243b53}"
APPLY="${APPLY:-0}"
API="https://api.stripe.com/v1"

command -v python >/dev/null 2>&1 && PY=python || PY=python3

case "$STRIPE_SECRET_KEY" in
  sk_test_*) MODE="TEST" ;;
  sk_live_*) MODE="LIVE" ;;
  rk_*)      MODE="restricted key" ;;
  *)         MODE="unrecognized key prefix" ;;
esac

echo "Stripe key:  $MODE"
echo "Brand name:  $BRAND_NAME"
echo "Product:     $PRODUCT_NAME"
echo "Descriptor:  $DESCRIPTOR"
echo "Brand color: $BRAND_COLOR"
if [ "$APPLY" = "1" ]; then echo "Mode:        APPLY (writing changes)"; else echo "Mode:        DRY RUN (no changes — set APPLY=1 to write)"; fi
echo

# api METHOD PATH [curl args...] -> raw JSON
api() { local m=$1 p=$2; shift 2; curl -s -X "$m" "$API$p" -u "$STRIPE_SECRET_KEY:" "$@"; }
# field JSON 'python-expr on d' -> value
field() { "$PY" -c "import sys,json
try: d=json.load(sys.stdin)
except Exception: print(''); sys.exit()
print($1)"; }

err_of() { field "(d.get('error') or {}).get('message') or ''"; }

# --- 1. Account (public name, statement descriptor, brand color) ---
acct=$(api GET /account)
acct_err=$(printf '%s' "$acct" | err_of)
if [ -n "$acct_err" ]; then
  echo "! could not read account: $acct_err"
  exit 1
fi
acct_id=$(printf '%s' "$acct" | field "d.get('id','')")
cur_name=$(printf '%s' "$acct" | field "(d.get('business_profile') or {}).get('name') or ''")
cur_desc=$(printf '%s' "$acct" | field "((d.get('settings') or {}).get('payments') or {}).get('statement_descriptor') or ''")
echo "Account: $acct_id"
echo "  public name:           '$cur_name'  ->  '$BRAND_NAME'"
echo "  statement descriptor:  '$cur_desc'  ->  '$DESCRIPTOR'"
if [ "$APPLY" = "1" ]; then
  resp=$(api POST "/accounts/$acct_id" \
    --data-urlencode "business_profile[name]=$BRAND_NAME" \
    --data-urlencode "settings[payments][statement_descriptor]=$DESCRIPTOR" \
    --data-urlencode "settings[branding][primary_color]=$BRAND_COLOR")
  e=$(printf '%s' "$resp" | err_of)
  if [ -n "$e" ]; then
    echo "  ! account update rejected: $e"
    echo "    -> set these in Dashboard: Settings → Branding and Public details"
  else
    echo "  ✓ account updated"
  fi
fi
echo

# --- 2. Subscription product (name + statement descriptor) ---
prod="${STRIPE_PRODUCT_ID:-}"
if [ -z "$prod" ] && [ -n "${STRIPE_PRICE_ID:-}" ]; then
  prod=$(api GET "/prices/$STRIPE_PRICE_ID" | field "d.get('product','') if isinstance(d.get('product',''),str) else (d.get('product') or {}).get('id','')")
fi

if [ -z "$prod" ]; then
  echo "No STRIPE_PRICE_ID / STRIPE_PRODUCT_ID set. Active products:"
  api GET "/products?active=true&limit=100" | "$PY" -c "import sys,json
for p in json.load(sys.stdin).get('data',[]):
    print('   ', p['id'], '|', repr(p.get('name')), '| descriptor=', repr(p.get('statement_descriptor')))"
  echo "Re-run with STRIPE_PRICE_ID=price_... (or STRIPE_PRODUCT_ID=prod_...) to rename the right one."
else
  cur=$(api GET "/products/$prod")
  e=$(printf '%s' "$cur" | err_of)
  if [ -n "$e" ]; then
    echo "! could not read product $prod: $e"
  else
    pn=$(printf '%s' "$cur" | field "d.get('name') or ''")
    pd=$(printf '%s' "$cur" | field "d.get('statement_descriptor') or ''")
    echo "Product: $prod"
    echo "  name:                  '$pn'  ->  '$PRODUCT_NAME'"
    echo "  statement descriptor:  '$pd'  ->  '$DESCRIPTOR'"
    if [ "$APPLY" = "1" ]; then
      resp=$(api POST "/products/$prod" \
        --data-urlencode "name=$PRODUCT_NAME" \
        --data-urlencode "statement_descriptor=$DESCRIPTOR")
      e=$(printf '%s' "$resp" | err_of)
      if [ -n "$e" ]; then echo "  ! product update rejected: $e"; else echo "  ✓ product updated"; fi
    fi
  fi
fi

echo
echo "Remaining manual step: upload the KyberCrypt logo/icon in"
echo "  Dashboard → Settings → Branding  (image upload isn't scripted here)."
[ "$APPLY" = "1" ] || echo "This was a DRY RUN. Re-run with APPLY=1 to write the changes above."
