package hem

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// capture records the last request a test server received, so a test can assert
// the exact wire format against the reference PHP suite (hem-api-tester).
type capture struct {
	method string
	path   string
	auth   string
	body   map[string]interface{}
}

func serve(t *testing.T, reply string) (*Client, *capture) {
	t.Helper()
	rec := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.method = r.Method
		rec.path = r.URL.Path
		rec.auth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &rec.body)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, Config{}), rec
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestSearchKeysWireFormat(t *testing.T) {
	c, rec := serve(t, `{"offset":0,"total":1,"listed":1,"list":[{"kid":"ab","descr":"`+b64("WG:if:x")+`"}]}`)

	total, keys, err := c.SearchKeys(context.Background(), "", []byte("WG:if:"), 0, 0)
	if err != nil {
		t.Fatalf("SearchKeys: %v", err)
	}
	if rec.path != "/api/keymgmt/search" || rec.method != "POST" {
		t.Fatalf("got %s %s", rec.method, rec.path)
	}
	// The '^' anchor belongs on the base64 text, not on the raw bytes.
	if got, want := rec.body["descr"], "^"+b64("WG:if:"); got != want {
		t.Errorf("descr = %v, want %v", got, want)
	}
	if _, ok := rec.body["offset"]; !ok {
		t.Error("offset must always be sent")
	}
	if _, ok := rec.body["limit"]; ok {
		t.Error("limit must be omitted when <= 0 so the device default applies")
	}
	if rec.auth != "" {
		t.Error("anonymous search must not send an Authorization header")
	}
	if total != 1 || len(keys) != 1 || string(keys[0].Descr) != "WG:if:x" {
		t.Errorf("total=%d keys=%+v", total, keys)
	}
}

func TestSearchKeysSendsLimit(t *testing.T) {
	c, rec := serve(t, `{"total":0,"listed":0,"list":[]}`)
	if _, _, err := c.SearchKeys(context.Background(), "tok", []byte("WG:pr:"), 30, 50); err != nil {
		t.Fatalf("SearchKeys: %v", err)
	}
	if rec.body["offset"] != json.Number("30") && rec.body["offset"] != float64(30) {
		t.Errorf("offset = %v", rec.body["offset"])
	}
	if rec.body["limit"] != json.Number("50") && rec.body["limit"] != float64(50) {
		t.Errorf("limit = %v", rec.body["limit"])
	}
	if rec.auth != "Bearer tok" {
		t.Errorf("auth = %q", rec.auth)
	}
}

func TestHmacSelfECDHWireFormat(t *testing.T) {
	c, rec := serve(t, `{"mac":"`+b64("0123456789abcdef")+`"}`)

	pub := []byte("32-byte-curve25519-public-key---")
	mac, err := c.HmacHash(context.Background(), "tok", "kid1", []byte("msg"),
		CryptoOpts{Alg: "SHA2-256", PubKey: pub})
	if err != nil {
		t.Fatalf("HmacHash: %v", err)
	}
	if rec.path != "/api/crypto/hmac/hash" {
		t.Fatalf("path = %s", rec.path)
	}
	if rec.body["kid"] != "kid1" || rec.body["alg"] != "SHA2-256" {
		t.Errorf("body = %v", rec.body)
	}
	if rec.body["msg"] != b64("msg") {
		t.Errorf("msg = %v", rec.body["msg"])
	}
	if rec.body["pubkey"] != base64.StdEncoding.EncodeToString(pub) {
		t.Errorf("pubkey = %v", rec.body["pubkey"])
	}
	if _, ok := rec.body["ext_kid"]; ok {
		t.Error("ext_kid must be absent when PubKey is used")
	}
	if string(mac) != "0123456789abcdef" {
		t.Errorf("mac = %q", mac)
	}
}

func TestCipherWrapCarriesCtx(t *testing.T) {
	c, rec := serve(t, `{"wrapped":"`+b64("wrapped-bytes")+`"}`)

	_, err := c.CipherWrap(context.Background(), "tok", "kid1", []byte("psk"),
		CryptoOpts{Alg: "AES256", ExtKID: "kid1", Ctx: []byte("ENC-WG-PSK-v1")})
	if err != nil {
		t.Fatalf("CipherWrap: %v", err)
	}
	if rec.path != "/api/crypto/cipher/wrap" {
		t.Fatalf("path = %s", rec.path)
	}
	if rec.body["ext_kid"] != "kid1" || rec.body["alg"] != "AES256" {
		t.Errorf("body = %v", rec.body)
	}
	if rec.body["ctx"] != b64("ENC-WG-PSK-v1") {
		t.Errorf("ctx = %v", rec.body["ctx"])
	}
}

func TestECDHOmitsAlgForRawSecret(t *testing.T) {
	c, rec := serve(t, `{"ecdh":"`+b64("32-byte-shared-secret-value-----")+`"}`)

	secret, err := c.ECDH(context.Background(), "tok", "kid1", CryptoOpts{PubKey: []byte("peer")})
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	if _, ok := rec.body["alg"]; ok {
		t.Error("alg must be omitted so the device returns the raw secret")
	}
	if len(secret) != 32 {
		t.Errorf("secret length = %d", len(secret))
	}
}

func TestOptionsRejectedWhenEndpointIgnoresThem(t *testing.T) {
	c, _ := serve(t, `{}`)
	ctx := context.Background()

	// The hmac endpoint has no ctx field; silently dropping it would produce a
	// MAC under a different key than the caller believes.
	if _, err := c.HmacHash(ctx, "t", "k", []byte("m"), CryptoOpts{Ctx: []byte("x")}); err == nil {
		t.Error("HmacHash must reject Ctx")
	}
	if _, err := c.ECDH(ctx, "t", "k", CryptoOpts{ExtKID: "a", PubKey: []byte("b")}); err == nil {
		t.Error("ECDH must reject ExtKID and PubKey together")
	}
	if _, err := c.CipherWrap(ctx, "t", "k", []byte("m"), CryptoOpts{AAD: []byte("x")}); err == nil {
		t.Error("CipherWrap must reject AAD")
	}
	if _, err := c.HmacHash(ctx, "t", "k", make([]byte, maxCryptoMsg+1), CryptoOpts{}); err == nil {
		t.Error("HmacHash must reject a message over the device limit")
	}
	if _, err := c.CipherWrap(ctx, "t", "k", []byte("m"), CryptoOpts{Ctx: make([]byte, maxCtx+1)}); err == nil {
		t.Error("CipherWrap must reject an oversized ctx")
	}
}

func TestHmacVerifyReportsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotAcceptable) // 406 — the device rejected the MAC
	}))
	defer srv.Close()
	c := NewClient(srv.URL, Config{})

	err := c.HmacVerify(context.Background(), "tok", "kid", []byte("m"), []byte("mac"), CryptoOpts{})
	he, ok := err.(*HemError)
	if !ok {
		t.Fatalf("err = %v, want *HemError", err)
	}
	if he.Status != http.StatusNotAcceptable || he.Code != "http_406" {
		t.Errorf("status=%d code=%s", he.Status, he.Code)
	}
}

func TestTokenCacheHonoursNoCacheScopes(t *testing.T) {
	c := NewClient("https://example.invalid", Config{NoCacheScopes: []string{"keymgmt:use:"}})

	jwt := "h." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":`+
		strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)+`}`)) + ".s"

	c.cacheStore("keymgmt:list", jwt)
	c.cacheStore("keymgmt:use:abcd", jwt)

	if _, ok := c.cacheFind("keymgmt:list"); !ok {
		t.Error("keymgmt:list should be cached")
	}
	// A trailing ':' in NoCacheScopes matches by prefix, covering every KID.
	if _, ok := c.cacheFind("keymgmt:use:abcd"); ok {
		t.Error("keymgmt:use:* must not be cached")
	}
}

func TestTokenCacheDropsExpired(t *testing.T) {
	c := NewClient("https://example.invalid", Config{})
	expired := "h." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":`+
		strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)+`}`)) + ".s"

	c.cacheStore("keymgmt:list", expired)
	if _, ok := c.cacheFind("keymgmt:list"); ok {
		t.Error("an expired token must not be served from the cache")
	}
}

func TestClearKeysWipesSeed(t *testing.T) {
	c := NewClient("https://example.invalid", Config{})
	seed := []byte("seed-material-32-bytes-long-----")
	c.seed, c.seedID = seed, "eid"

	c.ClearKeys()
	for i, b := range seed {
		if b != 0 {
			t.Fatalf("seed byte %d not zeroed", i)
		}
	}
	if c.seed != nil || c.seedID != "" {
		t.Error("seed reference must be dropped")
	}
}

func TestAuthPasswordWithoutCachedKey(t *testing.T) {
	c, _ := serve(t, `{"eid":"E","spk":"`+b64("32-byte-device-public-key-------")+`","jti":"J"}`)
	c.keyCache = true

	_, err := c.AuthPassword(context.Background(), nil, "keymgmt:list", 300)
	he, ok := err.(*HemError)
	if !ok || he.Code != "auth_password_required" {
		t.Fatalf("err = %v, want auth_password_required", err)
	}
}
