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
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/pbkdf2"
)

const pbkdf2Iterations = 600_000

// HemError represents an error returned by the Encedo HSM API.
type HemError struct {
	Message string
	Code    string
	Status  int
	Data    interface{}
}

func (e *HemError) Error() string { return e.Message }

// Client is an Encedo HSM API client.
type Client struct {
	baseURL    string
	broker     string
	httpClient *http.Client
}

// NewClient creates a new Encedo HSM client.
// broker is the notification broker URL (e.g. "https://api.encedo.com").
// insecureSkipVerify disables TLS certificate verification (use for self-signed PPA certs).
func NewClient(hsmURL, broker string, insecureSkipVerify bool) *Client {
	return &Client{
		baseURL: strings.TrimRight(hsmURL, "/"),
		broker:  strings.TrimRight(broker, "/"),
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecureSkipVerify},
				DisableKeepAlives:   true,
			},
		},
	}
}

// req performs an HTTP request and unmarshals the JSON response into out.
// Mirrors #req() in hem-sdk.js.
func (c *Client) req(method, url string, body interface{}, token string, out interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return &HemError{Message: fmt.Sprintf("marshal request body: %v", err), Code: "encode_error"}
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return &HemError{Message: fmt.Sprintf("create request: %v", err), Code: "request_error"}
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &HemError{Message: fmt.Sprintf("network error: %v", err), Code: "network"}
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return &HemError{Message: fmt.Sprintf("read response: %v", err), Code: "read_error"}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var data interface{}
		_ = json.Unmarshal(respData, &data)
		return &HemError{
			Message: fmt.Sprintf("HEM %s %s -> HTTP %d", method, url, resp.StatusCode),
			Code:    fmt.Sprintf("http_%d", resp.StatusCode),
			Status:  resp.StatusCode,
			Data:    data,
		}
	}

	if out != nil {
		dec := json.NewDecoder(bytes.NewReader(respData))
		dec.UseNumber()
		if err := dec.Decode(out); err != nil {
			return &HemError{Message: fmt.Sprintf("unmarshal response: %v", err), Code: "decode_error"}
		}
	}
	return nil
}

// Checkin performs the 3-step HSM clock synchronisation.
// Mirrors hemCheckin() in hem-sdk.js.
func (c *Client) Checkin() error {
	var step1 map[string]interface{}
	if err := c.req("GET", c.baseURL+"/api/system/checkin", nil, "", &step1); err != nil {
		return err
	}
	if _, ok := step1["check"]; !ok {
		return &HemError{Message: "HSM checkin failed (no check field)", Code: "checkin_error"}
	}

	var step2 map[string]interface{}
	if err := c.req("POST", c.broker+"/checkin", step1, "", &step2); err != nil {
		return err
	}
	if _, ok := step2["checked"]; !ok {
		return &HemError{Message: "broker checkin failed (no checked field)", Code: "broker_error"}
	}

	var step3 map[string]interface{}
	if err := c.req("POST", c.baseURL+"/api/system/checkin", step2, "", &step3); err != nil {
		return err
	}
	if _, ok := step3["status"]; !ok {
		return &HemError{Message: "HSM checkin step 3 failed (no status field)", Code: "checkin_error"}
	}
	return nil
}

// zeroBytes overwrites a byte slice with zeros to remove sensitive data from memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// deriveX25519 runs PBKDF2-SHA256 on password with salt=eid and returns
// the seed and the derived X25519 public key in standard base64.
// Mirrors #deriveX25519() in hem-sdk.js.
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
// Mirrors #buildEjwt() in hem-sdk.js.
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

// AuthPassword authenticates with a local password and returns a JWT token.
// Mirrors authorizePassword() in hem-sdk.js.
func (c *Client) AuthPassword(password []byte, scope string, expSeconds int) (string, error) {
	var challenge struct {
		EID string `json:"eid"`
		SPK string `json:"spk"`
		JTI string `json:"jti"`
		Exp int64  `json:"exp"`
		Lbl string `json:"lbl"`
	}
	if err := c.req("GET", c.baseURL+"/api/auth/token", nil, "", &challenge); err != nil {
		return "", err
	}

	seed, pubKeyB64, err := deriveX25519(password, challenge.EID)
	if err != nil {
		return "", err
	}

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
	zeroBytes(seed) // seed no longer needed — token is derived, only ejwt matters now
	if err != nil {
		return "", err
	}

	var resp struct {
		Token string `json:"token"`
	}
	if err := c.req("POST", c.baseURL+"/api/auth/token", map[string]string{"auth": ejwt}, "", &resp); err != nil {
		return "", err
	}
	if resp.Token == "" {
		return "", &HemError{Message: "no token in auth response", Code: "auth_failed"}
	}
	return resp.Token, nil
}

// AuthRemote authenticates via mobile push notification (broker polling).
// Mirrors authorizeRemote() in hem-sdk.js.
// If ctx is cancelled, returns ctx.Err() — caller should fall back to password auth.
func (c *Client) AuthRemote(ctx context.Context, scope string, pollInterval, pollTimeout time.Duration) (string, error) {
	// Step 1: broker session
	var session map[string]interface{}
	if err := c.req("GET", c.broker+"/notify/session", nil, "", &session); err != nil {
		return "", err
	}

	// Step 2: request auth from device (pass full session data + scope)
	session["scope"] = scope
	var challenge map[string]interface{}
	if err := c.req("POST", c.baseURL+"/api/auth/ext/request", session, "", &challenge); err != nil {
		return "", err
	}

	// Step 3: forward challenge to broker
	var event struct {
		EventID string `json:"eventid"`
	}
	if err := c.req("POST", c.broker+"/notify/event/new", challenge, "", &event); err != nil {
		return "", err
	}
	if event.EventID == "" {
		return "", &HemError{Message: "no eventid from broker", Code: "broker_error"}
	}

	// Step 4: poll
	deadline := time.Now().Add(pollTimeout)
	var result map[string]interface{}

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pollInterval):
		}

		fmt.Fprintf(os.Stderr, "Waiting for mobile confirmation...\n")

		pollReq, err := http.NewRequestWithContext(ctx, "GET",
			c.broker+"/notify/event/check/"+event.EventID, nil)
		if err != nil {
			return "", &HemError{Message: fmt.Sprintf("create poll request: %v", err), Code: "request_error"}
		}

		pollResp, err := c.httpClient.Do(pollReq)
		if err != nil {
			return "", &HemError{Message: fmt.Sprintf("broker poll network error: %v", err), Code: "network"}
		}

		if pollResp.StatusCode == 202 {
			pollResp.Body.Close()
			continue
		}
		if pollResp.StatusCode != 200 {
			pollResp.Body.Close()
			return "", &HemError{
				Message: fmt.Sprintf("broker poll HTTP %d", pollResp.StatusCode),
				Code:    fmt.Sprintf("http_%d", pollResp.StatusCode),
				Status:  pollResp.StatusCode,
			}
		}

		if err := json.NewDecoder(pollResp.Body).Decode(&result); err != nil {
			pollResp.Body.Close()
			return "", &HemError{Message: fmt.Sprintf("decode poll result: %v", err), Code: "decode_error"}
		}
		pollResp.Body.Close()
		break
	}

	if result == nil {
		return "", &HemError{Message: "remote auth timed out", Code: "timeout"}
	}

	// Step 5a: check denial
	if deny, _ := result["deny"].(bool); deny {
		return "", &HemError{Message: "auth denied by user", Code: "denied"}
	}
	authreply, _ := result["authreply"].(string)
	if authreply == "" {
		return "", &HemError{Message: "missing authreply", Code: "broker_error"}
	}

	// Step 5b: exchange authreply for JWT
	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := c.req("POST", c.baseURL+"/api/auth/ext/token",
		map[string]string{"authreply": authreply}, "", &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Token == "" {
		return "", &HemError{Message: "no token in ext/token response", Code: "auth_failed"}
	}
	return tokenResp.Token, nil
}

// KeyEntry represents a single key entry returned by ListKeys and SearchKeys.
type KeyEntry struct {
	KID     string
	Label   string
	Type    string
	Created int64
	Updated int64
	Descr   []byte // raw binary, nil if not set
}

// listResp is the shared response shape for list/search endpoints.
type listResp struct {
	Total  int `json:"total"`
	Listed int `json:"listed"`
	List   []struct {
		KID     string `json:"kid"`
		Label   string `json:"label"`
		Type    string `json:"type"`
		Created int64  `json:"created"`
		Updated int64  `json:"updated"`
		Descr   string `json:"descr"` // base64-encoded by HEM API; decoded to []byte in KeyEntry
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

// ListKeys returns a paginated list of keys from the HSM repository.
// Scope: keymgmt:list
func (c *Client) ListKeys(token string, offset, limit int) (total int, keys []KeyEntry, err error) {
	var resp listResp
	url := fmt.Sprintf("%s/api/keymgmt/list/%d/%d", c.baseURL, offset, limit)
	if err := c.req("GET", url, nil, token, &resp); err != nil {
		return 0, nil, err
	}
	return resp.Total, parseKeyList(resp), nil
}

// SearchKeys searches the HSM key repository by the descr field.
// pattern is raw binary matched against the binary descr stored in the HSM.
// Prefix '^' or suffix '$' anchoring is applied to the base64-encoded pattern,
// not to the raw bytes (HEM API convention).
// Pass token="" for anonymous access when allow_keysearch is enabled on the device
// and len(pattern) >= 6 bytes.
// Scope: keymgmt:search (token optional if allow_keysearch device config is set)
//
// TODO: suffix match — HEM API likely supports <base64>$ (ends-with), but this
// is not documented in the PHP SDK and needs verification against FW source.
func (c *Client) SearchKeys(token string, pattern []byte, prefixMatch bool, offset, limit int) (total int, keys []KeyEntry, err error) {
	encoded := base64.StdEncoding.EncodeToString(pattern)
	if prefixMatch {
		encoded = "^" + encoded
	}
	body := map[string]interface{}{
		"descr":  encoded,
		"offset": offset,
		"limit":  limit,
	}
	var resp listResp
	if err := c.req("POST", c.baseURL+"/api/keymgmt/search", body, token, &resp); err != nil {
		return 0, nil, err
	}
	return resp.Total, parseKeyList(resp), nil
}

// CreateKey generates a new key in the HSM repository.
// keyType: CURVE25519, ED25519, AES256, etc.
// mode: optional key mode for NIST ECC keys ("ECDH", "ExDSA", "ECDH,ExDSA"); pass "" to omit.
// descr: optional raw binary description (up to 128 bytes); pass nil to omit.
// Returns the KID (32-char hex) of the created key.
// Scope: keymgmt:gen
func (c *Client) CreateKey(token, label, keyType string, descr []byte, mode string) (kid string, err error) {
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
	if err := c.req("POST", c.baseURL+"/api/keymgmt/create", body, token, &resp); err != nil {
		return "", err
	}
	if resp.KID == "" {
		return "", &HemError{Message: "no kid in create response", Code: "create_error"}
	}
	return resp.KID, nil
}

// ImportKey imports an external public key into the HSM repository.
// Supported types: CURVE25519, ED25519, SECP256R1, MLKEM512, etc.
// pubkey: raw binary public key bytes.
// descr: optional raw binary description (up to 128 bytes); pass nil to omit.
// mode: optional key mode for NIST ECC keys; pass "" to omit.
// Returns the KID (32-char hex) of the imported key.
// Scope: keymgmt:imp
func (c *Client) ImportKey(token, label, keyType string, pubkey, descr []byte, mode string) (kid string, err error) {
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
	if err := c.req("POST", c.baseURL+"/api/keymgmt/import", body, token, &resp); err != nil {
		return "", err
	}
	if resp.KID == "" {
		return "", &HemError{Message: "no kid in import response", Code: "import_error"}
	}
	return resp.KID, nil
}

// UpdateKey updates a key's label and/or description in the HSM repository.
// At least one of label or descr must be provided; returns an error otherwise.
// Pass label="" to leave the label unchanged.
// Pass descr=nil to leave the description unchanged.
// Scope: keymgmt:upd
func (c *Client) UpdateKey(token, kid, label string, descr []byte) error {
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
	return c.req("POST", c.baseURL+"/api/keymgmt/update", body, token, nil)
}

// CipherEncryptResult holds the output of a CipherEncrypt call.
type CipherEncryptResult struct {
	Ciphertext []byte // raw binary
	IV         []byte // raw binary (12B for GCM)
	Tag        []byte // raw binary (16B for GCM), nil for non-GCM modes
}

// CipherEncrypt encrypts data using a key stored in the HSM.
// alg: "AES256-GCM", "AES128-GCM", "AES256-CBC", etc.
// aad: additional authenticated data for GCM modes (raw binary); pass nil to omit.
// ctx: context field (raw binary); pass nil to omit.
// The IV is generated by the HSM.
// Scope: keymgmt:use:<KID>
func (c *Client) CipherEncrypt(token, kid, alg string, plaintext, aad, ctx []byte) (*CipherEncryptResult, error) {
	body := map[string]interface{}{
		"kid": kid,
		"alg": alg,
		"msg": base64.StdEncoding.EncodeToString(plaintext),
	}
	if len(aad) > 0 {
		body["aad"] = base64.StdEncoding.EncodeToString(aad)
	}
	if len(ctx) > 0 {
		body["ctx"] = base64.StdEncoding.EncodeToString(ctx)
	}
	var resp struct {
		Ciphertext string `json:"ciphertext"`
		IV         string `json:"iv"`
		Tag        string `json:"tag"`
	}
	if err := c.req("POST", c.baseURL+"/api/crypto/cipher/encrypt", body, token, &resp); err != nil {
		return nil, err
	}
	result := &CipherEncryptResult{}
	result.Ciphertext, _ = base64.StdEncoding.DecodeString(resp.Ciphertext)
	result.IV, _ = base64.StdEncoding.DecodeString(resp.IV)
	if resp.Tag != "" {
		result.Tag, _ = base64.StdEncoding.DecodeString(resp.Tag)
	}
	return result, nil
}

// CipherDecrypt decrypts data using a key stored in the HSM.
// alg: "AES256-GCM", "AES128-GCM", "AES256-CBC", etc.
// iv: initialization vector (raw binary); required for GCM/CBC.
// tag: GCM authentication tag (raw binary, 16B); required for GCM modes.
// aad: additional authenticated data (raw binary); pass nil to omit.
// ctx: context field (raw binary); pass nil to omit.
// pubkey: ephemeral X25519 public key for ECDH-based decryption (raw binary);
//         pass nil for direct AES key usage.
// Scope: keymgmt:use:<KID>
func (c *Client) CipherDecrypt(token, kid, alg string, ciphertext, iv, tag, aad, ctx, pubkey []byte) ([]byte, error) {
	body := map[string]interface{}{
		"kid": kid,
		"alg": alg,
		"msg": base64.StdEncoding.EncodeToString(ciphertext),
	}
	if len(iv) > 0 {
		body["iv"] = base64.StdEncoding.EncodeToString(iv)
	}
	if len(tag) > 0 {
		body["tag"] = base64.StdEncoding.EncodeToString(tag)
	}
	if len(aad) > 0 {
		body["aad"] = base64.StdEncoding.EncodeToString(aad)
	}
	if len(ctx) > 0 {
		body["ctx"] = base64.StdEncoding.EncodeToString(ctx)
	}
	if len(pubkey) > 0 {
		body["pubkey"] = base64.StdEncoding.EncodeToString(pubkey)
	}
	var resp struct {
		Plaintext string `json:"plaintext"`
	}
	if err := c.req("POST", c.baseURL+"/api/crypto/cipher/decrypt", body, token, &resp); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.Plaintext)
}

// GetPubKey retrieves the public key and metadata for a given key ID.
// Mirrors getPubKey() in hem-sdk.js.
func (c *Client) GetPubKey(token, kid string) (pubKey string, keyType string, updated int64, err error) {
	var resp struct {
		PubKey  string `json:"pubkey"`
		Type    string `json:"type"`
		Updated int64  `json:"updated"`
	}
	if err := c.req("GET", c.baseURL+"/api/keymgmt/get/"+kid, nil, token, &resp); err != nil {
		return "", "", 0, err
	}
	return resp.PubKey, resp.Type, resp.Updated, nil
}

// ECDH performs a Curve25519 ECDH operation on the HSM.
// kid is the private key ID (32-char hex) stored in the HSM.
// peerPubKeyBase64 is the peer's WireGuard public key in standard base64.
// Returns the raw 32-byte shared secret.
func (c *Client) ECDH(token, kid, peerPubKeyBase64 string) ([]byte, error) {
	body := map[string]string{
		"kid":    kid,
		"pubkey": peerPubKeyBase64,
	}
	var resp struct {
		ECDH string `json:"ecdh"`
	}
	if err := c.req("POST", c.baseURL+"/api/crypto/ecdh", body, token, &resp); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(resp.ECDH)
	if err != nil {
		return nil, fmt.Errorf("decode ECDH result: %w", err)
	}
	return raw, nil
}

// ECDHInternal performs ECDH entirely within the HSM between two stored keys.
// kid is the local private key, extKid is the peer's imported public key.
// Neither key value leaves the HSM.
func (c *Client) ECDHInternal(token, kid, extKid string) ([]byte, error) {
	body := map[string]string{
		"kid":     kid,
		"ext_kid": extKid,
	}
	var resp struct {
		ECDH string `json:"ecdh"`
	}
	if err := c.req("POST", c.baseURL+"/api/crypto/ecdh", body, token, &resp); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(resp.ECDH)
	if err != nil {
		return nil, fmt.Errorf("decode ECDH result: %w", err)
	}
	return raw, nil
}
