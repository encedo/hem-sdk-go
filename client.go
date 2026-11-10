// Package hem is a dependency-light Go client for the Encedo HEM (Hardware
// Encryption Module) REST API. Key material never leaves the device — the SDK
// only sends challenges and receives signatures, public keys or shared secrets.
//
// Binary in, binary out: every parameter and return value that carries key
// material, plaintext, ciphertext or a MAC is a []byte. Base64 encoding is an
// implementation detail of the wire format and is handled inside the methods.
//
// The optional fields shared by the /api/crypto/* endpoints (alg, ext_kid,
// pubkey, aad, ctx, iv, tag) are passed as a single CryptoOpts value. Each
// method documents which fields it honours and rejects the rest, so a field
// that the endpoint would ignore is reported instead of silently dropped.
package hem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/pbkdf2"
)

const (
	pbkdf2Iterations = 600_000

	// DefaultBroker is the Encedo notification broker used for checkin and
	// mobile-push authentication.
	DefaultBroker = "https://api.encedo.com"

	// DefaultTimeout bounds a single HTTP request to the device.
	DefaultTimeout = 10 * time.Second

	// maxCryptoMsg is the largest msg the device accepts on /api/crypto/*.
	maxCryptoMsg = 2048

	// maxCtx is the largest HKDF context, and salt, the device accepts
	// (hkdf_ctx / hkdf_salt, decoded, firmware 1.3).
	maxCtx = 128

	// tokenSkew keeps a cached token from being handed out moments before the
	// device would reject it as expired.
	tokenSkew = 5 * time.Second
)

// HemError represents an error returned by the Encedo HEM API.
type HemError struct {
	Message string
	Code    string
	Status  int
	Data    interface{}
}

func (e *HemError) Error() string {
	// The device explains itself in the response body — which argument it did
	// not like, which state it is in. Dropping that leaves a caller staring at
	// "HTTP 400" with nothing to act on, so it goes in the message.
	if detail := e.detail(); detail != "" {
		return e.Message + ": " + detail
	}
	return e.Message
}

// detail renders the device's response body compactly, preferring the fields it
// uses for error text over a dump of the whole object.
func (e *HemError) detail() string {
	switch v := e.Data.(type) {
	case nil:
		return ""
	case string:
		return v
	case map[string]interface{}:
		for _, key := range []string{"error", "message", "msg", "reason", "status"} {
			if s, ok := v[key].(string); ok && s != "" {
				return s
			}
		}
		out, err := json.Marshal(v)
		if err != nil || len(out) > 512 {
			return ""
		}
		return string(out)
	default:
		return ""
	}
}

// Config configures a Client. The zero value is valid: it selects the public
// broker, a 10 s request timeout, verified TLS and caching enabled.
type Config struct {
	// Broker is the notification broker URL. Empty selects DefaultBroker.
	Broker string

	// Timeout bounds a single HTTP request. Zero selects DefaultTimeout;
	// a negative value disables the timeout (the caller's context still applies).
	Timeout time.Duration

	// InsecureSkipVerify disables TLS certificate verification. Current PPA and
	// EPA firmware presents a certificate that verifies normally, so this is for
	// a device whose certificate has not been provisioned yet, or a test rig
	// standing in for one — not for ordinary use.
	InsecureSkipVerify bool

	// DisableTokenCache turns off JWT caching entirely.
	DisableTokenCache bool

	// NoCacheScopes lists scopes whose tokens are never cached. An entry ending
	// in ':' matches by prefix, so "keymgmt:use:" covers every per-key scope.
	NoCacheScopes []string

	// DisableKeyCache turns off caching of the X25519 seed derived from the
	// password. With caching on, AuthPassword(ctx, nil, …) issues further
	// tokens without the password and without a second PBKDF2 pass; the cost is
	// that password-equivalent material stays in process memory until
	// ClearKeys is called. A long-running process should cache the seed for the
	// startup burst and drop it once the tokens it needs are in hand.
	DisableKeyCache bool

	// Logf, when set, receives a line per request and response. It is the only
	// output the SDK produces — nothing is ever written to stdout or stderr.
	Logf func(format string, v ...interface{})
}

// Client is an Encedo HEM API client. It is safe for concurrent use.
type Client struct {
	baseURL    string
	broker     string
	timeout    time.Duration
	noCache    []string
	cacheOff   bool
	keyCache   bool
	logf       func(format string, v ...interface{})
	httpClient *http.Client

	mu     sync.Mutex
	tokens map[string]cachedToken
	seed   []byte // X25519 seed derived from the password
	seedID string // device eid the seed was derived for
}

type cachedToken struct {
	jwt string
	exp time.Time
}

// NewClient creates a client for the HEM at hsmURL.
func NewClient(hsmURL string, cfg Config) *Client {
	broker := cfg.Broker
	if broker == "" {
		broker = DefaultBroker
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < 0 {
		timeout = 0
	}
	return &Client{
		baseURL:  strings.TrimRight(hsmURL, "/"),
		broker:   strings.TrimRight(broker, "/"),
		timeout:  timeout,
		noCache:  append([]string(nil), cfg.NoCacheScopes...),
		cacheOff: cfg.DisableTokenCache,
		keyCache: !cfg.DisableKeyCache,
		logf:     cfg.Logf,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
				// The embedded device closes the connection after every
				// response; keep-alive would only produce stale sockets.
				DisableKeepAlives: true,
			},
		},
	}
}

func (c *Client) debugf(format string, v ...interface{}) {
	if c.logf != nil {
		c.logf(format, v...)
	}
}

// req performs an HTTP request and unmarshals the JSON response into out.
func (c *Client) req(ctx context.Context, method, url string, body interface{}, token string, out interface{}) error {
	_, err := c.do(ctx, method, url, body, token, out)
	return err
}

// do is req plus the HTTP status code, which the broker polling loop needs:
// an unanswered request comes back as 202, a success code that nonetheless
// means "keep waiting".
func (c *Client) do(ctx context.Context, method, url string, body interface{}, token string, out interface{}) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	var bodyReader io.Reader
	var bodyLen int
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, &HemError{Message: fmt.Sprintf("marshal request body: %v", err), Code: "encode_error"}
		}
		bodyReader = bytes.NewReader(data)
		bodyLen = len(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return 0, &HemError{Message: fmt.Sprintf("create request: %v", err), Code: "request_error"}
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// The embedded HTTP server rejects chunked bodies with 411; an explicit
	// length is required even when the body is empty.
	if bodyReader != nil {
		req.ContentLength = int64(bodyLen)
	}
	c.debugf("HEM -> %s %s (%d B)", method, url, bodyLen)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		code := "network"
		switch ctx.Err() {
		case context.DeadlineExceeded:
			code = "timeout"
		case context.Canceled:
			code = "aborted"
		}
		return 0, &HemError{Message: fmt.Sprintf("%s %s: %v", method, url, err), Code: code}
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, &HemError{Message: fmt.Sprintf("read response: %v", err), Code: "read_error"}
	}
	c.debugf("HEM <- %d (%d B)", resp.StatusCode, len(respData))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var data interface{}
		_ = json.Unmarshal(respData, &data)
		return resp.StatusCode, &HemError{
			Message: fmt.Sprintf("HEM %s %s -> HTTP %d", method, url, resp.StatusCode),
			Code:    fmt.Sprintf("http_%d", resp.StatusCode),
			Status:  resp.StatusCode,
			Data:    data,
		}
	}

	// A 2xx with no body is a valid answer for the endpoints that only signal
	// success (key update); decoding it would fail on EOF. hmac/verify is not
	// one of them: its verdict is in the body (see HmacVerify).
	if out != nil && len(respData) > 0 {
		dec := json.NewDecoder(bytes.NewReader(respData))
		dec.UseNumber()
		if err := dec.Decode(out); err != nil {
			return resp.StatusCode, &HemError{Message: fmt.Sprintf("unmarshal response: %v", err), Code: "decode_error"}
		}
	}
	return resp.StatusCode, nil
}

// -- Token and key cache -----------------------------------------------------

func (c *Client) cacheable(scope string) bool {
	if c.cacheOff {
		return false
	}
	for _, s := range c.noCache {
		if s == scope || (strings.HasSuffix(s, ":") && strings.HasPrefix(scope, s)) {
			return false
		}
	}
	return true
}

func (c *Client) cacheFind(scope string) (string, bool) {
	if !c.cacheable(scope) {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for s, t := range c.tokens {
		if !t.exp.IsZero() && now.After(t.exp.Add(-tokenSkew)) {
			delete(c.tokens, s)
		}
	}
	t, ok := c.tokens[scope]
	if !ok {
		return "", false
	}
	return t.jwt, true
}

func (c *Client) cacheStore(scope, jwt string) {
	if !c.cacheable(scope) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tokens == nil {
		c.tokens = make(map[string]cachedToken)
	}
	c.tokens[scope] = cachedToken{jwt: jwt, exp: jwtExp(jwt)}
}

// ClearCache drops every cached JWT. The derived key, if any, is kept.
func (c *Client) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens = nil
}

// ClearKeys drops the cached derived key and every cached JWT. Call it on
// logout, or once a long-running process holds the tokens it needs.
func (c *Client) ClearKeys() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens = nil
	zeroBytes(c.seed)
	c.seed = nil
	c.seedID = ""
}

// TokenExpiry returns the exp claim of a scoped token, or the zero time if it
// carries none.
//
// Callers need this rather than the lifetime they asked for. A device may issue
// a token shorter than the request, and its clock is its own: a run on
// 2026-08-11 asked for eight hours and the session ended after seven and a half.
// Anything counting down towards the end of a session — a status line, a
// countdown in an interface — has to read the token rather than the request, or
// it will be confidently wrong in the direction that strands somebody.
func TokenExpiry(token string) time.Time { return jwtExp(token) }

// jwtExp returns the exp claim of a JWT, or the zero time if it has none.
func jwtExp(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}

// -- Checkin -----------------------------------------------------------------

// Checkin performs the 3-step clock synchronisation between the device and the
// Encedo backend. Call it once, before anything else. No authorization needed.
func (c *Client) Checkin(ctx context.Context) error {
	var step1 map[string]interface{}
	if err := c.req(ctx, "GET", c.baseURL+"/api/system/checkin", nil, "", &step1); err != nil {
		return err
	}
	if _, ok := step1["check"]; !ok {
		return &HemError{Message: "HEM checkin failed (no check field)", Code: "checkin_error"}
	}

	var step2 map[string]interface{}
	if err := c.req(ctx, "POST", c.broker+"/checkin", step1, "", &step2); err != nil {
		return err
	}
	if _, ok := step2["checked"]; !ok {
		return &HemError{Message: "broker checkin failed (no checked field)", Code: "broker_error"}
	}

	var step3 map[string]interface{}
	if err := c.req(ctx, "POST", c.baseURL+"/api/system/checkin", step2, "", &step3); err != nil {
		return err
	}
	if _, ok := step3["status"]; !ok {
		return &HemError{Message: "HEM checkin step 3 failed (no status field)", Code: "checkin_error"}
	}
	return nil
}

// -- Authentication ----------------------------------------------------------

// zeroBytes overwrites a byte slice with zeros to remove sensitive data from memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// deriveX25519 runs PBKDF2-SHA256 over password with salt=eid and returns the
// seed together with the derived X25519 public key in standard base64.
func deriveX25519(password []byte, eid string) (seed []byte, pubKeyB64 string, err error) {
	seed = pbkdf2.Key(password, []byte(eid), pbkdf2Iterations, 32, sha256.New)
	pubKeyBytes, err := curve25519.X25519(seed, curve25519.Basepoint)
	if err != nil {
		zeroBytes(seed)
		return nil, "", fmt.Errorf("X25519 public key derivation: %w", err)
	}
	return seed, base64.StdEncoding.EncodeToString(pubKeyBytes), nil
}

// buildEjwt constructs the eJWT used for password authentication.
// Header: {"ecdh":"x25519","alg":"HS256","typ":"JWT"}
// Signature: HMAC-SHA256(header.payload, X25519(seed, devicePubKey))
func buildEjwt(seed []byte, devicePubKeyB64 string, payload map[string]interface{}) (string, error) {
	hdrJSON, err := json.Marshal(map[string]string{"ecdh": "x25519", "alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	hdr := base64.RawURLEncoding.EncodeToString(hdrJSON)
	bdy := base64.RawURLEncoding.EncodeToString(payloadJSON)
	input := hdr + "." + bdy

	spkBytes, err := base64.StdEncoding.DecodeString(devicePubKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode device public key: %w", err)
	}
	sharedSecret, err := curve25519.X25519(seed, spkBytes)
	if err != nil {
		return "", fmt.Errorf("X25519 shared secret: %w", err)
	}
	defer zeroBytes(sharedSecret)

	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write([]byte(input))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return input + "." + sig, nil
}

// AuthPassword authenticates with the local password and returns a scoped JWT.
//
// Pass password=nil to reuse the key derived by an earlier call — the second
// and further scopes then need neither the password nor another PBKDF2 pass.
// This requires Config.DisableKeyCache to be false (the default) and an earlier
// successful call against the same device; otherwise it fails with code
// "auth_password_required".
//
// The caller owns password and is responsible for zeroing it; the SDK does not,
// precisely so that it can be passed to several AuthPassword calls in a row.
func (c *Client) AuthPassword(ctx context.Context, password []byte, scope string, expSeconds int) (string, error) {
	if jwt, ok := c.cacheFind(scope); ok {
		return jwt, nil
	}

	var challenge struct {
		EID string `json:"eid"`
		SPK string `json:"spk"`
		JTI string `json:"jti"`
		Exp int64  `json:"exp"`
		Lbl string `json:"lbl"`
	}
	if err := c.req(ctx, "GET", c.baseURL+"/api/auth/token", nil, "", &challenge); err != nil {
		return "", err
	}

	seed, pubKeyB64, err := c.seedFor(password, challenge.EID)
	if err != nil {
		return "", err
	}
	defer zeroBytes(seed)

	iat := time.Now().Unix() - 5
	payload := map[string]interface{}{
		"jti":   challenge.JTI,
		"aud":   challenge.SPK,
		"exp":   iat + int64(expSeconds),
		"iat":   iat,
		"iss":   pubKeyB64,
		"scope": scope,
	}

	ejwt, err := buildEjwt(seed, challenge.SPK, payload)
	if err != nil {
		return "", err
	}

	var resp struct {
		Token string `json:"token"`
	}
	if err := c.req(ctx, "POST", c.baseURL+"/api/auth/token", map[string]string{"auth": ejwt}, "", &resp); err != nil {
		return "", err
	}
	if resp.Token == "" {
		return "", &HemError{Message: "no token in auth response", Code: "auth_failed"}
	}
	c.cacheStore(scope, resp.Token)
	return resp.Token, nil
}

// seedFor returns a private copy of the X25519 seed for the given device eid,
// deriving it from the password when there is nothing usable in the cache.
// The copy is what makes ClearKeys safe to call while a request is in flight:
// it wipes the cached seed without touching the one the request is signing with.
func (c *Client) seedFor(password []byte, eid string) (seed []byte, pubKeyB64 string, err error) {
	if c.keyCache {
		c.mu.Lock()
		var cached []byte
		if c.seed != nil && c.seedID == eid {
			cached = append([]byte(nil), c.seed...)
		}
		c.mu.Unlock()
		if cached != nil {
			pub, err := curve25519.X25519(cached, curve25519.Basepoint)
			if err != nil {
				zeroBytes(cached)
				return nil, "", fmt.Errorf("X25519 public key derivation: %w", err)
			}
			return cached, base64.StdEncoding.EncodeToString(pub), nil
		}
	}
	if password == nil {
		return nil, "", &HemError{
			Message: "no cached key for this device: a password is required",
			Code:    "auth_password_required",
		}
	}

	seed, pubKeyB64, err = deriveX25519(password, eid)
	if err != nil {
		return nil, "", err
	}
	if c.keyCache {
		c.mu.Lock()
		zeroBytes(c.seed)
		c.seed, c.seedID = append([]byte(nil), seed...), eid
		c.mu.Unlock()
	}
	return seed, pubKeyB64, nil
}

// RemoteOpts tunes the mobile-push authentication flow.
type RemoteOpts struct {
	// PollInterval is the delay between broker polls. Zero selects 2 s.
	PollInterval time.Duration
	// PollTimeout gives up on an unanswered request. Zero selects 60 s.
	PollTimeout time.Duration
	// OnPending, when set, is called before every poll. The SDK writes nothing
	// itself — this is where a CLI prints "waiting for confirmation".
	OnPending func()
}

// AuthRemote authenticates via a mobile push notification and returns a scoped
// JWT. The user approves the request in the Encedo authenticator app.
// Cancelling ctx aborts the wait and returns ctx.Err().
func (c *Client) AuthRemote(ctx context.Context, scope string, opts RemoteOpts) (string, error) {
	if jwt, ok := c.cacheFind(scope); ok {
		return jwt, nil
	}
	pollInterval := opts.PollInterval
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	pollTimeout := opts.PollTimeout
	if pollTimeout <= 0 {
		pollTimeout = 60 * time.Second
	}

	// Step 1: broker session
	var session map[string]interface{}
	if err := c.req(ctx, "GET", c.broker+"/notify/session", nil, "", &session); err != nil {
		return "", err
	}

	// Step 2: request auth from the device (full session data + scope)
	session["scope"] = scope
	var challenge map[string]interface{}
	if err := c.req(ctx, "POST", c.baseURL+"/api/auth/ext/request", session, "", &challenge); err != nil {
		return "", err
	}

	// Step 3: forward the challenge to the broker
	var event struct {
		EventID string `json:"eventid"`
	}
	if err := c.req(ctx, "POST", c.broker+"/notify/event/new", challenge, "", &event); err != nil {
		return "", err
	}
	if event.EventID == "" {
		return "", &HemError{Message: "no eventid from broker", Code: "broker_error"}
	}

	// Step 4: poll until the user approves, denies, or the deadline passes
	deadline := time.Now().Add(pollTimeout)
	var result map[string]interface{}

	for time.Now().Before(deadline) {
		if opts.OnPending != nil {
			opts.OnPending()
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pollInterval):
		}

		var polled map[string]interface{}
		status, err := c.do(ctx, "GET", c.broker+"/notify/event/check/"+event.EventID, nil, "", &polled)
		if err != nil {
			return "", err
		}
		if status == http.StatusAccepted {
			continue // the user has not answered yet
		}
		result = polled
		break
	}

	if result == nil {
		return "", &HemError{Message: "remote auth timed out", Code: "timeout"}
	}

	if deny, _ := result["deny"].(bool); deny {
		return "", &HemError{Message: "auth denied by user", Code: "denied"}
	}
	authreply, _ := result["authreply"].(string)
	if authreply == "" {
		return "", &HemError{Message: "missing authreply", Code: "broker_error"}
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := c.req(ctx, "POST", c.baseURL+"/api/auth/ext/token",
		map[string]string{"authreply": authreply}, "", &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Token == "" {
		return "", &HemError{Message: "no token in ext/token response", Code: "auth_failed"}
	}
	c.cacheStore(scope, tokenResp.Token)
	return tokenResp.Token, nil
}

// -- Key management ----------------------------------------------------------

// KeyEntry represents a single key entry returned by ListKeys and SearchKeys.
type KeyEntry struct {
	KID     string
	Label   string
	Type    string
	Created int64
	Updated int64
	Descr   []byte // raw binary, nil if not set
}

// listResp is the shared response shape for the list and search endpoints.
type listResp struct {
	Offset int `json:"offset"`
	Total  int `json:"total"`
	Listed int `json:"listed"`
	List   []struct {
		KID     string `json:"kid"`
		Label   string `json:"label"`
		Type    string `json:"type"`
		Created int64  `json:"created"`
		Updated int64  `json:"updated"`
		Descr   string `json:"descr"` // base64-encoded by the HEM API
	} `json:"list"`
}

func parseKeyList(resp listResp) []KeyEntry {
	entries := make([]KeyEntry, 0, len(resp.List))
	for _, e := range resp.List {
		entry := KeyEntry{
			KID: e.KID, Label: e.Label, Type: e.Type,
			Created: e.Created, Updated: e.Updated,
		}
		if e.Descr != "" {
			entry.Descr, _ = base64.StdEncoding.DecodeString(e.Descr)
		}
		entries = append(entries, entry)
	}
	return entries
}

// ListKeys returns a page of the key repository.
// Scope: keymgmt:list
func (c *Client) ListKeys(ctx context.Context, token string, offset, limit int) (total int, keys []KeyEntry, err error) {
	var resp listResp
	url := fmt.Sprintf("%s/api/keymgmt/list/%d/%d", c.baseURL, offset, limit)
	if err := c.req(ctx, "GET", url, nil, token, &resp); err != nil {
		return 0, nil, err
	}
	return resp.Total, parseKeyList(resp), nil
}

// SearchKeys returns the keys whose descr field starts with pattern.
//
// pattern is raw binary; the '^' anchor the device expects is applied to the
// base64 form, not to the bytes. Only prefix matching is available — a suffix
// anchor ('$') is neither documented nor exercised by the certification test
// suite, so it is left out until the firmware behaviour is confirmed.
//
// limit <= 0 leaves the device default (15 entries) in place. Paginate by
// adding len(keys) to offset until offset reaches total.
//
// Pass token="" for anonymous access, which the device permits when
// allow_keysearch is configured and pattern is at least 6 bytes long.
// Scope: keymgmt:search (or keymgmt:list + auth:ext:pair)
func (c *Client) SearchKeys(ctx context.Context, token string, pattern []byte, offset, limit int) (total int, keys []KeyEntry, err error) {
	if offset < 0 {
		offset = 0
	}
	body := map[string]interface{}{
		"descr":  "^" + base64.StdEncoding.EncodeToString(pattern),
		"offset": offset,
	}
	if limit > 0 {
		body["limit"] = limit
	}
	var resp listResp
	if err := c.req(ctx, "POST", c.baseURL+"/api/keymgmt/search", body, token, &resp); err != nil {
		return 0, nil, err
	}
	return resp.Total, parseKeyList(resp), nil
}

// CreateKey generates a new key in the repository and returns its KID.
// keyType is CURVE25519, ED25519, AES256, … ; mode is the usage mode required
// by NIST ECC keys ("ECDH", "ExDSA", "ECDH,ExDSA") and may be empty.
// descr is raw binary, up to 128 bytes, and may be nil.
// Scope: keymgmt:gen
func (c *Client) CreateKey(ctx context.Context, token, label, keyType string, descr []byte, mode string) (kid string, err error) {
	body := map[string]interface{}{
		"label": label,
		"type":  keyType,
	}
	if len(descr) > 0 {
		body["descr"] = base64.StdEncoding.EncodeToString(descr)
	}
	if mode != "" {
		body["mode"] = mode
	}
	var resp struct {
		KID string `json:"kid"`
	}
	if err := c.req(ctx, "POST", c.baseURL+"/api/keymgmt/create", body, token, &resp); err != nil {
		return "", err
	}
	if resp.KID == "" {
		return "", &HemError{Message: "no kid in create response", Code: "create_error"}
	}
	return resp.KID, nil
}

// ImportKey imports an external public key and returns its KID.
// pubkey is raw binary — for NIST ECC keys a compressed SEC1 point (0x02/0x03||X),
// which also requires mode to be set.
// Scope: keymgmt:imp
func (c *Client) ImportKey(ctx context.Context, token, label, keyType string, pubkey, descr []byte, mode string) (kid string, err error) {
	body := map[string]interface{}{
		"label":  label,
		"type":   keyType,
		"pubkey": base64.StdEncoding.EncodeToString(pubkey),
	}
	if len(descr) > 0 {
		body["descr"] = base64.StdEncoding.EncodeToString(descr)
	}
	if mode != "" {
		body["mode"] = mode
	}
	var resp struct {
		KID string `json:"kid"`
	}
	if err := c.req(ctx, "POST", c.baseURL+"/api/keymgmt/import", body, token, &resp); err != nil {
		return "", err
	}
	if resp.KID == "" {
		return "", &HemError{Message: "no kid in import response", Code: "import_error"}
	}
	return resp.KID, nil
}

// UpdateKey updates a key's label and/or description.
// An empty label omits the field, a nil descr omits it likewise, and at least
// one of the two must be set.
//
// Note that the reference test suite always sends both (hem-api-tester,
// test_10.php), and a device may reject an update that carries only a
// description. Passing the key's current label alongside a new description is
// the safe shape.
// Scope: keymgmt:upd
func (c *Client) UpdateKey(ctx context.Context, token, kid, label string, descr []byte) error {
	if label == "" && descr == nil {
		return &HemError{Message: "UpdateKey: label or descr must be set", Code: "invalid_arg"}
	}
	body := map[string]interface{}{"kid": kid}
	if label != "" {
		body["label"] = label
	}
	if descr != nil {
		body["descr"] = base64.StdEncoding.EncodeToString(descr)
	}
	return c.req(ctx, "POST", c.baseURL+"/api/keymgmt/update", body, token, nil)
}

// DeleteKey removes a key from the repository. The operation is irreversible:
// a private key deleted here cannot be recovered from anywhere else.
// Scope: keymgmt:del
func (c *Client) DeleteKey(ctx context.Context, token, kid string) error {
	return c.req(ctx, "DELETE", c.baseURL+"/api/keymgmt/delete/"+kid, nil, token, nil)
}

// PubKeyInfo is the public half of a key stored in the HEM.
type PubKeyInfo struct {
	PubKey  []byte // raw binary
	Type    string
	Updated int64
}

// GetPubKey retrieves the public key and metadata for a key ID.
//
// Scope: keymgmt:get reads any key's public part; keymgmt:use:<KID> covers that
// one key and serves as well. A key id the device cannot resolve comes back as
// HTTP 406, not 404 — the status describes existence here, not permission, and
// a caller checking whether a key is present has to read it that way.
func (c *Client) GetPubKey(ctx context.Context, token, kid string) (PubKeyInfo, error) {
	var resp struct {
		PubKey  string `json:"pubkey"`
		Type    string `json:"type"`
		Updated int64  `json:"updated"`
	}
	if err := c.req(ctx, "GET", c.baseURL+"/api/keymgmt/get/"+kid, nil, token, &resp); err != nil {
		return PubKeyInfo{}, err
	}
	raw, err := base64.StdEncoding.DecodeString(resp.PubKey)
	if err != nil {
		return PubKeyInfo{}, &HemError{Message: fmt.Sprintf("decode pubkey: %v", err), Code: "decode_error"}
	}
	return PubKeyInfo{PubKey: raw, Type: resp.Type, Updated: resp.Updated}, nil
}

// -- Cryptography ------------------------------------------------------------

// CryptoOpts carries the optional fields shared by the /api/crypto/* endpoints.
// The zero value uses the key at kid directly and lets the device pick its
// default algorithm.
//
// ExtKID and PubKey both name a peer public key, which turns the operation into
// an indirect one: the device runs ECDH between kid and the peer key and uses
// the shared secret as the operation's key. The peer key must be of the same
// type as kid. Naming kid's own public key is legal and yields a self-ECDH key
// that exists only inside the device.
//
// Each method rejects the fields its endpoint does not accept, so an option
// that would be ignored on the wire is reported as "invalid_arg" instead.
type CryptoOpts struct {
	Alg    string // ECDH: hash over the shared secret, "" for raw. HMAC: SHA2-256/384/512, SHA3-256/384/512. Cipher: AES256-GCM, AES256-CBC, … Wrap: AES128/AES192/AES256
	ExtKID string // peer public key already stored in the HEM
	PubKey []byte // raw peer public key; must not be combined with ExtKID
	AAD    []byte // cipher encrypt/decrypt, GCM modes only
	Ctx    []byte // HKDF context (hkdf_ctx), max 128 bytes — cipher and wrap/unwrap, modes 1/2
	Salt   []byte // HKDF salt (hkdf_salt), max 128 bytes — cipher and wrap/unwrap, modes 1/2
	IV     []byte // explicit IV — cipher decrypt and wrap/unwrap
	Tag    []byte // GCM authentication tag — cipher decrypt only
}

// applyPeer writes the ext_kid/pubkey selector into body.
func (o CryptoOpts) applyPeer(body map[string]interface{}) error {
	if o.ExtKID != "" && len(o.PubKey) > 0 {
		return &HemError{Message: "set ExtKID or PubKey, not both", Code: "invalid_arg"}
	}
	if o.ExtKID != "" {
		body["ext_kid"] = o.ExtKID
	} else if len(o.PubKey) > 0 {
		body["pubkey"] = base64.StdEncoding.EncodeToString(o.PubKey)
	}
	return nil
}

// applyHKDF writes hkdf_ctx and hkdf_salt into body. Firmware 1.3 reads only
// these names; the `ctx` field older builds of this SDK sent is ignored by the
// device, so a key derived "with" it was derived without any context.
func (o CryptoOpts) applyHKDF(body map[string]interface{}) {
	if len(o.Ctx) > 0 {
		body["hkdf_ctx"] = base64.StdEncoding.EncodeToString(o.Ctx)
	}
	if len(o.Salt) > 0 {
		body["hkdf_salt"] = base64.StdEncoding.EncodeToString(o.Salt)
	}
}

// reject reports the options set by the caller that the endpoint does not accept.
func (o CryptoOpts) reject(op string, allowed ...string) error {
	ok := func(name string) bool {
		for _, a := range allowed {
			if a == name {
				return true
			}
		}
		return false
	}
	var bad []string
	if o.Alg != "" && !ok("alg") {
		bad = append(bad, "Alg")
	}
	if len(o.AAD) > 0 && !ok("aad") {
		bad = append(bad, "AAD")
	}
	if len(o.Ctx) > 0 && !ok("ctx") {
		bad = append(bad, "Ctx")
	}
	if len(o.Salt) > 0 && !ok("ctx") {
		bad = append(bad, "Salt")
	}
	if len(o.IV) > 0 && !ok("iv") {
		bad = append(bad, "IV")
	}
	if len(o.Tag) > 0 && !ok("tag") {
		bad = append(bad, "Tag")
	}
	if len(bad) > 0 {
		return &HemError{
			Message: fmt.Sprintf("%s does not accept %s", op, strings.Join(bad, ", ")),
			Code:    "invalid_arg",
		}
	}
	if len(o.Ctx) > maxCtx {
		return &HemError{
			Message: fmt.Sprintf("%s: ctx is %d bytes, max %d", op, len(o.Ctx), maxCtx),
			Code:    "invalid_arg",
		}
	}
	if len(o.Salt) > maxCtx {
		return &HemError{
			Message: fmt.Sprintf("%s: salt is %d bytes, max %d", op, len(o.Salt), maxCtx),
			Code:    "invalid_arg",
		}
	}
	return nil
}

// checkMsgSize guards the device's 2048-byte limit on /api/crypto/* payloads,
// which otherwise surfaces as an opaque HTTP 400.
func checkMsgSize(op string, msg []byte) error {
	if len(msg) > maxCryptoMsg {
		return &HemError{
			Message: fmt.Sprintf("%s: message is %d bytes, max %d", op, len(msg), maxCryptoMsg),
			Code:    "invalid_arg",
		}
	}
	return nil
}

// ECDH runs a Curve25519 (or NIST ECC) ECDH on the device and returns the
// shared secret. Set opts.PubKey for a peer key held in software, opts.ExtKID
// for one already imported into the HEM — the latter keeps both operands inside
// the device. opts.Alg hashes the result; leave it empty for the raw secret,
// which is what the WireGuard Noise handshake needs.
// Honours: Alg, ExtKID, PubKey. Scope: keymgmt:use:<KID>
func (c *Client) ECDH(ctx context.Context, token, kid string, opts CryptoOpts) ([]byte, error) {
	if err := opts.reject("ECDH", "alg"); err != nil {
		return nil, err
	}
	body := map[string]interface{}{"kid": kid}
	if err := opts.applyPeer(body); err != nil {
		return nil, err
	}
	if opts.Alg != "" {
		body["alg"] = opts.Alg
	}
	var resp struct {
		ECDH string `json:"ecdh"`
	}
	if err := c.req(ctx, "POST", c.baseURL+"/api/crypto/ecdh", body, token, &resp); err != nil {
		return nil, err
	}
	if resp.ECDH == "" {
		return nil, &HemError{Message: "no ecdh in response", Code: "ecdh_error"}
	}
	raw, err := base64.StdEncoding.DecodeString(resp.ECDH)
	if err != nil {
		return nil, &HemError{Message: fmt.Sprintf("decode ECDH result: %v", err), Code: "decode_error"}
	}
	return raw, nil
}

// HmacHash computes an HMAC over msg (max 2048 bytes) with a key in the HEM.
// With opts.ExtKID or opts.PubKey the MAC key is the ECDH shared secret rather
// than the key at kid, so pointing at kid's own public key produces a MAC key
// that never exists outside the device.
// Honours: Alg, ExtKID, PubKey. Scope: keymgmt:use:<KID>
func (c *Client) HmacHash(ctx context.Context, token, kid string, msg []byte, opts CryptoOpts) ([]byte, error) {
	if err := opts.reject("HmacHash", "alg"); err != nil {
		return nil, err
	}
	if err := checkMsgSize("HmacHash", msg); err != nil {
		return nil, err
	}
	body := map[string]interface{}{
		"kid": kid,
		"msg": base64.StdEncoding.EncodeToString(msg),
	}
	if err := opts.applyPeer(body); err != nil {
		return nil, err
	}
	if opts.Alg != "" {
		body["alg"] = opts.Alg
	}
	var resp struct {
		MAC string `json:"mac"`
	}
	if err := c.req(ctx, "POST", c.baseURL+"/api/crypto/hmac/hash", body, token, &resp); err != nil {
		return nil, err
	}
	if resp.MAC == "" {
		return nil, &HemError{Message: "no mac in hmac/hash response", Code: "hmac_error"}
	}
	raw, err := base64.StdEncoding.DecodeString(resp.MAC)
	if err != nil {
		return nil, &HemError{Message: fmt.Sprintf("decode mac: %v", err), Code: "decode_error"}
	}
	return raw, nil
}

// HmacVerify checks a MAC on the device. It returns nil when the MAC is valid
// and a *HemError otherwise — the comparison happens inside the HEM, so a
// caller never has to write a constant-time compare of its own.
//
// Firmware 1.3 answers a MAC that does not match with 200 and
// {"verified":false}, not with an HTTP error, so the body is the verdict: a
// false or a missing `verified` is Code "not_verified". Anything else from the
// device is an error as before.
// opts must match the HmacHash call that produced the MAC.
// Honours: Alg, ExtKID, PubKey. Scope: keymgmt:use:<KID>
func (c *Client) HmacVerify(ctx context.Context, token, kid string, msg, mac []byte, opts CryptoOpts) error {
	if err := opts.reject("HmacVerify", "alg"); err != nil {
		return err
	}
	if err := checkMsgSize("HmacVerify", msg); err != nil {
		return err
	}
	body := map[string]interface{}{
		"kid": kid,
		"msg": base64.StdEncoding.EncodeToString(msg),
		"mac": base64.StdEncoding.EncodeToString(mac),
	}
	if err := opts.applyPeer(body); err != nil {
		return err
	}
	if opts.Alg != "" {
		body["alg"] = opts.Alg
	}
	var resp struct {
		Verified *bool `json:"verified"`
	}
	if err := c.req(ctx, "POST", c.baseURL+"/api/crypto/hmac/verify", body, token, &resp); err != nil {
		return err
	}
	if resp.Verified == nil || !*resp.Verified {
		return &HemError{Message: "HEM: the MAC does not verify", Code: "not_verified"}
	}
	return nil
}

// CipherResult holds the output of CipherEncrypt.
type CipherResult struct {
	Ciphertext []byte
	IV         []byte // generated by the device
	Tag        []byte // GCM modes only, nil otherwise
}

// CipherEncrypt encrypts plaintext (max 2048 bytes) with a key in the HEM.
// The IV is generated by the device. For ECB the plaintext length must be a
// multiple of 16 bytes.
// Honours: Alg, ExtKID, PubKey, AAD, Ctx. Scope: keymgmt:use:<KID>
func (c *Client) CipherEncrypt(ctx context.Context, token, kid string, plaintext []byte, opts CryptoOpts) (*CipherResult, error) {
	if err := opts.reject("CipherEncrypt", "alg", "aad", "ctx"); err != nil {
		return nil, err
	}
	if err := checkMsgSize("CipherEncrypt", plaintext); err != nil {
		return nil, err
	}
	body := map[string]interface{}{
		"kid": kid,
		"msg": base64.StdEncoding.EncodeToString(plaintext),
	}
	if err := opts.applyPeer(body); err != nil {
		return nil, err
	}
	if opts.Alg != "" {
		body["alg"] = opts.Alg
	}
	if len(opts.AAD) > 0 {
		body["aad"] = base64.StdEncoding.EncodeToString(opts.AAD)
	}
	opts.applyHKDF(body)
	var resp struct {
		Ciphertext string `json:"ciphertext"`
		IV         string `json:"iv"`
		Tag        string `json:"tag"`
	}
	if err := c.req(ctx, "POST", c.baseURL+"/api/crypto/cipher/encrypt", body, token, &resp); err != nil {
		return nil, err
	}
	if resp.Ciphertext == "" {
		return nil, &HemError{Message: "no ciphertext in encrypt response", Code: "cipher_error"}
	}
	out := &CipherResult{}
	out.Ciphertext, _ = base64.StdEncoding.DecodeString(resp.Ciphertext)
	out.IV, _ = base64.StdEncoding.DecodeString(resp.IV)
	if resp.Tag != "" {
		out.Tag, _ = base64.StdEncoding.DecodeString(resp.Tag)
	}
	return out, nil
}

// CipherDecrypt decrypts ciphertext with a key in the HEM. opts.IV is required
// for CBC and GCM, opts.Tag for GCM; the remaining options must match the
// CipherEncrypt call.
// Honours: Alg, ExtKID, PubKey, AAD, Ctx, IV, Tag. Scope: keymgmt:use:<KID>
func (c *Client) CipherDecrypt(ctx context.Context, token, kid string, ciphertext []byte, opts CryptoOpts) ([]byte, error) {
	if err := opts.reject("CipherDecrypt", "alg", "aad", "ctx", "iv", "tag"); err != nil {
		return nil, err
	}
	if err := checkMsgSize("CipherDecrypt", ciphertext); err != nil {
		return nil, err
	}
	body := map[string]interface{}{
		"kid": kid,
		"msg": base64.StdEncoding.EncodeToString(ciphertext),
	}
	if err := opts.applyPeer(body); err != nil {
		return nil, err
	}
	if opts.Alg != "" {
		body["alg"] = opts.Alg
	}
	if len(opts.IV) > 0 {
		body["iv"] = base64.StdEncoding.EncodeToString(opts.IV)
	}
	if len(opts.Tag) > 0 {
		body["tag"] = base64.StdEncoding.EncodeToString(opts.Tag)
	}
	if len(opts.AAD) > 0 {
		body["aad"] = base64.StdEncoding.EncodeToString(opts.AAD)
	}
	opts.applyHKDF(body)
	var resp struct {
		Plaintext string `json:"plaintext"`
	}
	if err := c.req(ctx, "POST", c.baseURL+"/api/crypto/cipher/decrypt", body, token, &resp); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return nil, &HemError{Message: fmt.Sprintf("decode plaintext: %v", err), Code: "decode_error"}
	}
	return raw, nil
}

// CipherWrap wraps key material with a key-encryption key held in the HEM
// (NIST AES key wrap — 32 bytes in, 40 bytes out, deterministic).
// With opts.ExtKID or opts.PubKey the KEK is the ECDH shared secret; opts.Ctx
// then domain-separates it from other wrap uses of the same key, and must be
// repeated verbatim on unwrap.
// Honours: Alg, ExtKID, PubKey, Ctx, IV. Scope: keymgmt:use:<KID>
func (c *Client) CipherWrap(ctx context.Context, token, kid string, data []byte, opts CryptoOpts) ([]byte, error) {
	if err := opts.reject("CipherWrap", "alg", "ctx", "iv"); err != nil {
		return nil, err
	}
	if err := checkMsgSize("CipherWrap", data); err != nil {
		return nil, err
	}
	body := map[string]interface{}{
		"kid": kid,
		"msg": base64.StdEncoding.EncodeToString(data),
	}
	if err := opts.applyPeer(body); err != nil {
		return nil, err
	}
	if opts.Alg != "" {
		body["alg"] = opts.Alg
	}
	opts.applyHKDF(body)
	if len(opts.IV) > 0 {
		body["iv"] = base64.StdEncoding.EncodeToString(opts.IV)
	}
	var resp struct {
		Wrapped string `json:"wrapped"`
	}
	if err := c.req(ctx, "POST", c.baseURL+"/api/crypto/cipher/wrap", body, token, &resp); err != nil {
		return nil, err
	}
	if resp.Wrapped == "" {
		return nil, &HemError{Message: "no wrapped in wrap response", Code: "cipher_error"}
	}
	raw, err := base64.StdEncoding.DecodeString(resp.Wrapped)
	if err != nil {
		return nil, &HemError{Message: fmt.Sprintf("decode wrapped: %v", err), Code: "decode_error"}
	}
	return raw, nil
}

// CipherUnwrap reverses CipherWrap. opts must match the wrap call exactly —
// a differing Ctx yields a different KEK and the unwrap fails.
// Honours: Alg, ExtKID, PubKey, Ctx, IV. Scope: keymgmt:use:<KID>
func (c *Client) CipherUnwrap(ctx context.Context, token, kid string, wrapped []byte, opts CryptoOpts) ([]byte, error) {
	if err := opts.reject("CipherUnwrap", "alg", "ctx", "iv"); err != nil {
		return nil, err
	}
	if err := checkMsgSize("CipherUnwrap", wrapped); err != nil {
		return nil, err
	}
	body := map[string]interface{}{
		"kid": kid,
		"msg": base64.StdEncoding.EncodeToString(wrapped),
	}
	if err := opts.applyPeer(body); err != nil {
		return nil, err
	}
	if opts.Alg != "" {
		body["alg"] = opts.Alg
	}
	opts.applyHKDF(body)
	if len(opts.IV) > 0 {
		body["iv"] = base64.StdEncoding.EncodeToString(opts.IV)
	}
	var resp struct {
		Unwrapped string `json:"unwrapped"`
	}
	if err := c.req(ctx, "POST", c.baseURL+"/api/crypto/cipher/unwrap", body, token, &resp); err != nil {
		return nil, err
	}
	if resp.Unwrapped == "" {
		return nil, &HemError{Message: "no unwrapped in unwrap response", Code: "cipher_error"}
	}
	raw, err := base64.StdEncoding.DecodeString(resp.Unwrapped)
	if err != nil {
		return nil, &HemError{Message: fmt.Sprintf("decode unwrapped: %v", err), Code: "decode_error"}
	}
	return raw, nil
}

// -- System ------------------------------------------------------------------

// Version describes the device hardware, bootloader and firmware.
type Version struct {
	HWV  string `json:"hwv"`
	BLV  string `json:"blv"`
	FWV  string `json:"fwv"`
	FWS  string `json:"fws"`
	Conf string `json:"conf"`
}

// GetVersion reads the device version. No authorization required, which makes
// it the natural probe for "is a device reachable at this address".
func (c *Client) GetVersion(ctx context.Context) (Version, error) {
	var v Version
	if err := c.req(ctx, "GET", c.baseURL+"/api/system/version", nil, "", &v); err != nil {
		return Version{}, err
	}
	return v, nil
}

// GetStatus reads the device runtime status, including the failure-state flag
// (fls_state) that gates every cryptographic operation. No authorization required.
func (c *Client) GetStatus(ctx context.Context) (map[string]interface{}, error) {
	var s map[string]interface{}
	if err := c.req(ctx, "GET", c.baseURL+"/api/system/status", nil, "", &s); err != nil {
		return nil, err
	}
	return s, nil
}
