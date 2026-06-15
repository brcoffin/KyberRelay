package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func readBody(resp *http.Response) []byte {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b
}

func corruptByte(t *testing.T, path string, offset int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if offset >= len(b) {
		t.Fatalf("offset %d beyond file size %d", offset, len(b))
	}
	b[offset] ^= 0xff
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// HTTP integration tests over httptest.Server, encoding the TC-SEC / TC-F matrix
// from TESTPLAN.md so the security guarantees run in CI instead of by hand.

func newTestServer(t *testing.T) (*server, *httptest.Server) {
	t.Helper()
	cfg := config{
		dataDir:    t.TempDir(),
		baseURL:    "http://kyber.test",
		host:       "kyber.test",
		maxBytes:   100 << 20,
		defaultTTL: time.Hour,
	}
	s, err := newServer(cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	ts := httptest.NewServer(s.handler())
	t.Cleanup(ts.Close)
	return s, ts
}

type tclient struct {
	t    *testing.T
	base string
	hc   *http.Client
}

func newClient(t *testing.T, base string) *tclient {
	jar, _ := cookiejar.New(nil)
	return &tclient{t: t, base: base, hc: &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// newRawClient keeps no cookie jar, so it never carries a session — used for
// pre-auth rate-limit/lockout loops (which key on the source IP, constant here).
func newRawClient(t *testing.T, base string) *tclient {
	return &tclient{t: t, base: base, hc: &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c *tclient) do(req *http.Request) *http.Response {
	c.t.Helper()
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	return resp
}

// form sends a urlencoded request. origin/csrf are added when non-empty.
func (c *tclient) form(method, path, origin, csrf string, vals url.Values) *http.Response {
	req, _ := http.NewRequest(method, c.base+path, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	return c.do(req)
}

func (c *tclient) get(path string) *http.Response {
	req, _ := http.NewRequest(http.MethodGet, c.base+path, nil)
	return c.do(req)
}

func (c *tclient) bearer(method, path, token string) *http.Response {
	req, _ := http.NewRequest(method, c.base+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return c.do(req)
}

// multipartSend posts a file to /api/send with origin + csrf.
func (c *tclient) multipartSend(origin, csrf, recipient, filename string, data []byte) *http.Response {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("recipient", recipient)
	fw, _ := mw.CreateFormFile("file", filename)
	fw.Write(data)
	mw.Close()
	req, _ := http.NewRequest(http.MethodPost, c.base+"/api/send", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	return c.do(req)
}

var csrfMeta = regexp.MustCompile(`csrf-token" content="([^"]*)"`)

func (c *tclient) appCSRF() string {
	resp := c.get("/app")
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	m := csrfMeta.FindSubmatch(buf.Bytes())
	if m == nil {
		c.t.Fatal("no csrf-token meta on /app (not logged in?)")
	}
	return string(m[1])
}

// registerLogin registers (which auto-logs-in) and returns the session's CSRF.
func (c *tclient) registerLogin(origin, user, pass string) string {
	resp := c.form(http.MethodPost, "/api/register", origin, "", url.Values{"username": {user}, "password": {pass}})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		c.t.Fatalf("register %s: status %d", user, resp.StatusCode)
	}
	return c.appCSRF()
}

func mustStatus(t *testing.T, resp *http.Response, want int, label string) {
	t.Helper()
	resp.Body.Close()
	if resp.StatusCode != want {
		t.Errorf("%s: status %d, want %d", label, resp.StatusCode, want)
	}
}

const goodPass = "correct-horse-battery"

func TestIntegration_AuthRequired(t *testing.T) {
	_, ts := newTestServer(t)
	c := newClient(t, ts.URL)
	mustStatus(t, c.form(http.MethodPost, "/api/send", ts.URL, "", nil), 401, "TC-SEC-20a send no session")
	mustStatus(t, c.get("/api/keys"), 401, "TC-SEC-20b keys no session")
	mustStatus(t, c.get("/app"), 303, "TC-SEC-20c app no session")
}

func TestIntegration_CSRF(t *testing.T) {
	_, ts := newTestServer(t)
	c := newClient(t, ts.URL)
	csrf := c.registerLogin(ts.URL, "alice", goodPass)

	mustStatus(t, c.form(http.MethodPost, "/api/2fa/setup", "", "", nil), 403, "TC-SEC-08 no origin")
	mustStatus(t, c.form(http.MethodPost, "/api/2fa/setup", ts.URL, "", nil), 403, "TC-SEC-09 no token")
	mustStatus(t, c.form(http.MethodPost, "/api/2fa/setup", ts.URL, "wrong", nil), 403, "TC-SEC-09 wrong token")
	mustStatus(t, c.form(http.MethodPost, "/api/2fa/setup", "http://evil.test", csrf, nil), 403, "TC-SEC-08 cross-origin")
	mustStatus(t, c.form(http.MethodPost, "/api/2fa/setup", ts.URL, csrf, nil), 200, "TC-SEC-09 correct token")
}

func TestIntegration_SendRoundtripAndPlanCap(t *testing.T) {
	s, ts := newTestServer(t)
	alice := newClient(t, ts.URL)
	acsrf := alice.registerLogin(ts.URL, "alice", goodPass)
	bob := newClient(t, ts.URL)
	bcsrf := bob.registerLogin(ts.URL, "bob", goodPass)

	payload := []byte("top secret payload")
	mustStatus(t, alice.multipartSend(ts.URL, acsrf, "bob", "secret.txt", payload), 200, "TC-F-07 send")
	mustStatus(t, alice.multipartSend(ts.URL, acsrf, "ghost", "x.txt", payload), 404, "TC-F-08 unknown recipient")

	// TC-SEC-14: free plan cap (25 MiB).
	mustStatus(t, alice.multipartSend(ts.URL, acsrf, "bob", "big.bin", make([]byte, 26<<20)), 413, "TC-SEC-14 plan cap")

	// TC-F-12/10: bob creates a decrypt key and downloads — roundtrip must match.
	kr := bob.form(http.MethodPost, "/api/keys", ts.URL, bcsrf, url.Values{"label": {"cli"}, "scope": {"decrypt"}})
	var key struct{ Token string }
	decodeJSON(t, kr, &key)
	inbox := bob.bearer(http.MethodGet, "/api/v1/inbox", key.Token)
	var ib struct {
		Messages []struct{ ID string } `json:"messages"`
	}
	decodeJSON(t, inbox, &ib)
	if len(ib.Messages) != 1 {
		t.Fatalf("TC-F-09 inbox: got %d messages, want 1", len(ib.Messages))
	}
	id := ib.Messages[0].ID
	dl := bob.bearer(http.MethodGet, "/api/v1/messages/"+id, key.Token)
	got := readBody(dl)
	if !bytes.Equal(got, payload) {
		t.Errorf("TC-F-10 roundtrip: got %q want %q", got, payload)
	}

	// TC-SEC-15: tamper the stored blob → download must fail.
	blob := s.msgs.blobPath("bob", id)
	corruptByte(t, blob, 40)
	mustStatus(t, bob.bearer(http.MethodGet, "/api/v1/messages/"+id, key.Token), 404, "TC-SEC-15 tampered blob")
}

func TestIntegration_CredentialRevocationOnPasswordChange(t *testing.T) {
	_, ts := newTestServer(t)
	bob := newClient(t, ts.URL)
	bcsrf := bob.registerLogin(ts.URL, "bob", goodPass)

	kr := bob.form(http.MethodPost, "/api/keys", ts.URL, bcsrf, url.Values{"label": {"k"}, "scope": {"decrypt"}})
	var key struct{ Token string }
	decodeJSON(t, kr, &key)
	mustStatus(t, bob.bearer(http.MethodGet, "/api/v1/inbox", key.Token), 200, "key works before change")

	mustStatus(t, bob.form(http.MethodPost, "/api/account/password", ts.URL, bcsrf,
		url.Values{"current_password": {goodPass}, "new_password": {"brand-new-passphrase-9"}}), 200, "TC-F-20 change pw")

	// TC-SEC-02: the old API key is revoked.
	mustStatus(t, bob.bearer(http.MethodGet, "/api/v1/inbox", key.Token), 401, "TC-SEC-02 key revoked")
	// TC-F-20b: new password logs in (fresh client/jar).
	fresh := newClient(t, ts.URL)
	mustStatus(t, fresh.form(http.MethodPost, "/api/login", ts.URL, "",
		url.Values{"username": {"bob"}, "password": {"brand-new-passphrase-9"}}), 200, "TC-F-20b new pw login")
}

func TestIntegration_LoginLockout(t *testing.T) {
	_, ts := newTestServer(t)
	newClient(t, ts.URL).registerLogin(ts.URL, "dave", goodPass) // create the account
	attacker := newRawClient(t, ts.URL)                          // session-less
	var last int
	for i := 0; i < 6; i++ {
		r := attacker.form(http.MethodPost, "/api/login", ts.URL, "", url.Values{"username": {"dave"}, "password": {"wrong-wrong-wrong"}})
		last = r.StatusCode
		r.Body.Close()
	}
	if last != 429 {
		t.Errorf("TC-SEC-13 lockout: last status %d, want 429", last)
	}
}

func TestIntegration_RegistrationRateLimit(t *testing.T) {
	_, ts := newTestServer(t)
	c := newRawClient(t, ts.URL) // no jar: each register stays pre-auth (no CSRF needed)
	var last int
	for i := 0; i < 22; i++ {
		r := c.form(http.MethodPost, "/api/register", ts.URL, "",
			url.Values{"username": {fmt.Sprintf("user%d", i)}, "password": {goodPass}})
		last = r.StatusCode
		r.Body.Close()
	}
	if last != 429 {
		t.Errorf("TC-SEC-11 reg rate limit: last status %d, want 429", last)
	}
}

func TestIntegration_PathTraversal(t *testing.T) {
	_, ts := newTestServer(t)
	c := newClient(t, ts.URL)
	c.registerLogin(ts.URL, "alice", goodPass)
	mustStatus(t, c.get("/api/msg/NOTAVALIDID"), 404, "TC-SEC-21 bad id")
}

func TestIntegration_WebhookSignature(t *testing.T) {
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_itest")
	s, ts := newTestServer(t)
	c := newClient(t, ts.URL)
	c.registerLogin(ts.URL, "bob", goodPass)

	// TC-SEC-19: bad signature rejected.
	bad, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/billing/webhook", strings.NewReader("{}"))
	bad.Header.Set("Stripe-Signature", "t=1,v1=deadbeef")
	mustStatus(t, c.do(bad), 400, "TC-SEC-19 bad signature")

	// TC-F-21: valid signature flips the plan to pro.
	payload := `{"type":"checkout.session.completed","data":{"object":{"client_reference_id":"bob","customer":"cus_1","subscription":"sub_1"}}}`
	ts2 := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, []byte("whsec_itest"))
	mac.Write([]byte(ts2 + "." + payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	good, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/billing/webhook", strings.NewReader(payload))
	good.Header.Set("Stripe-Signature", "t="+ts2+",v1="+sig)
	mustStatus(t, c.do(good), 200, "TC-F-21 valid webhook")

	if u, err := s.accounts.load("bob"); err != nil || u.Plan != "pro" {
		t.Errorf("TC-F-21 plan flip: plan=%q err=%v, want pro", u.Plan, err)
	}
}

// TC-F-14: an API key past its expiry is rejected (the one path the live run
// couldn't exercise without clock control).
func TestAPIKeyExpiry(t *testing.T) {
	store, err := newAPIKeyStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	expired, err := store.create("alice", "old", scopeSend, time.Now().Add(-time.Hour).Unix(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.authenticate(expired); err != errKeyExpired {
		t.Errorf("expired key: err=%v, want errKeyExpired", err)
	}
	valid, err := store.create("alice", "new", scopeSend, time.Now().Add(time.Hour).Unix(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.authenticate(valid); err != nil {
		t.Errorf("valid key: unexpected err %v", err)
	}
}
