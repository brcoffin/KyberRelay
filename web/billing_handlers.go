package main

import (
	"io"
	"net/http"
)

// GET /pricing — public plans page with an upgrade CTA.
func (s *server) handlePricing(w http.ResponseWriter, r *http.Request) {
	loggedIn := false
	plan := "free"
	csrf := ""
	if sess, ok := s.sessions.current(r); ok {
		loggedIn = true
		csrf = sess.csrf
		if u, err := s.accounts.load(sess.username); err == nil {
			plan = planFor(u.Plan).Name
		}
	}
	free := plans["free"]
	pro := plans["pro"]
	s.render(w, "pricing.html", map[string]any{
		"LoggedIn":  loggedIn,
		"CSRF":      csrf,
		"IsPro":     plan == "pro",
		"BillingOn": s.billing.enabled(),
		"ProPrice":  s.billing.proPrice,
		"FreeMax":   planMaxLabel(free),
		"FreeRet":   retentionLabel(free.TTL),
		"ProMax":    planMaxLabel(pro),
		"ProRet":    retentionLabel(pro.TTL),
	})
}

// POST /api/billing/checkout — create a Stripe Checkout session. Requires login.
func (s *server) handleCheckout(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if !s.billing.enabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing is not configured yet"})
		return
	}
	url, err := s.billing.createCheckoutSession(sess.username, s.cfg.baseURL)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not start checkout"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": url})
}

// GET /billing/success — landing after a completed checkout.
func (s *server) handleBillingSuccess(w http.ResponseWriter, r *http.Request) {
	s.render(w, "billing-success.html", nil)
}

// POST /api/billing/webhook — Stripe events (signature-verified). Flips plans.
func (s *server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	payload, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ev, ok := s.billing.verifyWebhook(payload, r.Header.Get("Stripe-Signature"))
	if !ok {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}

	switch ev.Type {
	case "checkout.session.completed":
		obj := ev.Data.Object
		if err := s.accounts.update(obj.ClientReferenceID, func(u *User) error {
			u.Plan = "pro"
			u.StripeCustomerID = obj.Customer
			u.StripeSubID = obj.Subscription
			return nil
		}); err == nil {
			s.audit.log("plan_upgraded", obj.ClientReferenceID, "stripe", "pro")
		}
	case "customer.subscription.deleted":
		if u, ok := s.accounts.findByStripeCustomer(ev.Data.Object.Customer); ok {
			if err := s.accounts.update(u.Username, func(u *User) error {
				u.Plan = "free"
				u.StripeSubID = ""
				return nil
			}); err == nil {
				s.audit.log("plan_downgraded", u.Username, "stripe", "free")
			}
		}
	}
	w.WriteHeader(http.StatusOK)
}
