package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Stripe billing via the REST API + webhook signature verification (no SDK).
// All Stripe config is via env; when unset, billing is "not configured" and the
// upgrade button is disabled, but the rest of the app runs normally.

type billingConfig struct {
	secretKey     string
	priceID       string
	webhookSecret string
	proPrice      string // display only, e.g. "$5/mo"
}

func loadBilling() *billingConfig {
	return &billingConfig{
		secretKey:     env("STRIPE_SECRET_KEY", ""),
		priceID:       env("STRIPE_PRICE_ID", ""),
		webhookSecret: env("STRIPE_WEBHOOK_SECRET", ""),
		proPrice:      env("PRO_PRICE", "$5/mo"),
	}
}

func (b *billingConfig) enabled() bool { return b.secretKey != "" && b.priceID != "" }

// createCheckoutSession creates a Stripe subscription Checkout Session and
// returns its hosted URL. client_reference_id carries the username so the
// webhook can attribute the payment.
func (b *billingConfig) createCheckoutSession(username, baseURL string) (string, error) {
	form := url.Values{}
	form.Set("mode", "subscription")
	form.Set("line_items[0][price]", b.priceID)
	form.Set("line_items[0][quantity]", "1")
	form.Set("success_url", baseURL+"/billing/success")
	form.Set("cancel_url", baseURL+"/pricing")
	form.Set("client_reference_id", username)
	form.Set("allow_promotion_codes", "true")

	req, err := http.NewRequest(http.MethodPost,
		"https://api.stripe.com/v1/checkout/sessions", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(b.secretKey, "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", &stripeAPIError{status: resp.StatusCode, body: string(body)}
	}
	var out struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.URL == "" {
		return "", &stripeAPIError{status: resp.StatusCode, body: string(body)}
	}
	return out.URL, nil
}

type stripeAPIError struct {
	status int
	body   string
}

func (e *stripeAPIError) Error() string {
	return "stripe API error " + strconv.Itoa(e.status)
}

// verifyWebhook validates the Stripe-Signature header (scheme v1) within a 5-min
// tolerance and returns the parsed event on success.
func (b *billingConfig) verifyWebhook(payload []byte, sigHeader string) (*stripeEvent, bool) {
	var ts string
	var sigs []string
	for _, part := range strings.Split(sigHeader, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.TrimSpace(kv[0]) {
		case "t":
			ts = strings.TrimSpace(kv[1])
		case "v1":
			sigs = append(sigs, strings.TrimSpace(kv[1]))
		}
	}
	if ts == "" || len(sigs) == 0 {
		return nil, false
	}
	tsi, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || absInt64(time.Now().Unix()-tsi) > 300 {
		return nil, false
	}
	mac := hmac.New(sha256.New, []byte(b.webhookSecret))
	mac.Write([]byte(ts + "."))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	matched := false
	for _, s := range sigs {
		if hmac.Equal([]byte(s), []byte(expected)) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, false
	}
	var ev stripeEvent
	if json.Unmarshal(payload, &ev) != nil {
		return nil, false
	}
	return &ev, true
}

func absInt64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// stripeEvent captures the fields we act on across the events we subscribe to.
type stripeEvent struct {
	Type string `json:"type"`
	Data struct {
		Object struct {
			ID                string `json:"id"`
			ClientReferenceID string `json:"client_reference_id"`
			Customer          string `json:"customer"`
			Subscription      string `json:"subscription"`
		} `json:"object"`
	} `json:"data"`
}
