package hem

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
	c, rec := serve(t, `{"offset":0,"total":9,"listed":1,"list":[{"kid":"ab","type":"ECDH,CURVE25519","descr":"`+b64("WG:if:x")+`"}]}`)

	page, err := c.SearchKeys(context.Background(), "", []byte("WG:if:"), SearchOpts{})
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
	if rec.body["offset"] != float64(0) || rec.body["limit"] != float64(PageSize) {
		t.Errorf("offset/limit = %v/%v, want 0/%d as the JS SDK sends", rec.body["offset"], rec.body["limit"], PageSize)
	}
	for _, k := range []string{"return_pubkey", "type", "mode"} {
		if _, ok := rec.body[k]; ok {
			t.Errorf("%s sent when not asked for", k)
		}
	}
	if rec.auth != "" {
		t.Error("anonymous search must not send an Authorization header")
	}
	if page.Total != 9 || page.Listed != 1 || len(page.Keys) != 1 {
		t.Fatalf("page = %+v", page)
	}
	k := page.Keys[0]
	if string(k.Descr) != "WG:if:x" || k.Type != "CURVE25519" || len(k.Flags) != 1 || k.Flags[0] != "ECDH" || k.PubKey != nil {
		t.Errorf("entry = %+v", k)
	}
}

func TestSearchKeysOptions(t *testing.T) {
	pub := "32-byte-curve25519-public-key---"
	c, rec := serve(t, `{"total":3,"listed":1,"list":[{"kid":"ab","type":"CURVE25519","pubkey":"`+b64(pub)+`"}]}`)
	page, err := c.SearchKeys(context.Background(), "tok", []byte("WG:pr:"), SearchOpts{
		Match: MatchSuffix, Offset: 30, Limit: 5, Type: "CURVE25519", Mode: "ECDH", ReturnPubkey: true})
	if err != nil {
		t.Fatalf("SearchKeys: %v", err)
	}
	if got, want := rec.body["descr"], b64("WG:pr:")+"$"; got != want {
		t.Errorf("descr = %v, want %v", got, want)
	}
	if rec.body["offset"] != float64(30) || rec.body["limit"] != float64(5) {
		t.Errorf("offset/limit = %v/%v", rec.body["offset"], rec.body["limit"])
	}
	if rec.body["type"] != "CURVE25519" || rec.body["mode"] != "ECDH" || rec.body["return_pubkey"] != true {
		t.Errorf("body = %v", rec.body)
	}
	if rec.auth != "Bearer tok" {
		t.Errorf("auth = %q", rec.auth)
	}
	if page.Offset != 30 || string(page.Keys[0].PubKey) != pub {
		t.Errorf("page = %+v", page)
	}

	if _, err := c.SearchKeys(context.Background(), "tok", []byte("WG"), SearchOpts{Match: MatchContains}); err != nil {
		t.Fatal(err)
	}
	if got, want := rec.body["descr"], b64("WG"); got != want {
		t.Errorf("contains: descr = %v, want %v", got, want)
	}
}

// A search walks on Listed until a page lists nothing: Total counts every
// record, so it cannot end the walk, and a page with public keys can end
// after 3 PQC keys with fewer than PageSize entries.
func TestSearchKeysAllPagesOnListed(t *testing.T) {
	var offsets []float64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		off := body["offset"].(float64)
		offsets = append(offsets, off)
		switch off {
		case 0:
			io.WriteString(w, `{"total":40,"listed":3,"list":[{"kid":"a"},{"kid":"b"},{"kid":"c"}]}`)
		case 3:
			io.WriteString(w, `{"total":40,"listed":1,"list":[{"kid":"d"}]}`)
		default:
			io.WriteString(w, `{"total":40,"listed":0,"list":[]}`)
		}
	}))
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL, Config{})
	keys, err := c.SearchKeysAll(context.Background(), "", []byte("WG:pr:"), SearchOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 4 || len(offsets) != 3 || offsets[1] != 3 || offsets[2] != 4 {
		t.Errorf("keys=%d offsets=%v", len(keys), offsets)
	}
}

// A list page counts a record failing its CRC in Listed without putting it in
// the list; paging on len(list) would read the next record twice.
func TestListKeysAllPagesOnListed(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/api/keymgmt/list/0/15/pubkey":
			io.WriteString(w, `{"total":3,"listed":2,"invalid":1,"list":[{"kid":"a"}]}`)
		default:
			io.WriteString(w, `{"total":3,"listed":1,"list":[{"kid":"c"}]}`)
		}
	}))
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL, Config{})
	keys, err := c.ListKeysAll(context.Background(), "tok", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || len(paths) != 2 || paths[1] != "/api/keymgmt/list/2/15/pubkey" {
		t.Errorf("keys=%v paths=%v", keys, paths)
	}
}

func fakeJWT(claims map[string]interface{}) string {
	raw, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

func TestTokenScopes(t *testing.T) {
	if got := TokenScopes(fakeJWT(map[string]interface{}{"scope": "keymgmt:get"})); len(got) != 1 || got[0] != "keymgmt:get" {
		t.Errorf("string scope: %v", got)
	}
	got := TokenScopes(fakeJWT(map[string]interface{}{"scope": []string{"keymgmt:use:ab", "keymgmt:get"}}))
	if len(got) != 2 || got[1] != "keymgmt:get" {
		t.Errorf("array scope: %v", got)
	}
	if TokenScopes("not.a.jwt") != nil || TokenScopes(fakeJWT(map[string]interface{}{})) != nil {
		t.Error("unreadable scope must be nil")
	}
}

// A cached token answers for every scope it holds, and only for what the
// token itself says it holds - not what was asked.
func TestTokenCacheCoversGrantedScopes(t *testing.T) {
	c := NewClient("https://hem.invalid", Config{})
	exp := time.Now().Add(time.Hour).Unix()
	jwt := fakeJWT(map[string]interface{}{"exp": exp, "scope": []string{"keymgmt:use:ab", "keymgmt:get"}})
	c.cacheStore([]string{"keymgmt:use:ab", "keymgmt:get", "keymgmt:search"}, jwt)

	for _, want := range [][]string{{"keymgmt:get"}, {"keymgmt:use:ab"}, {"keymgmt:get", "keymgmt:use:ab"}} {
		if got, ok := c.cacheFind(want); !ok || got != jwt {
			t.Errorf("%v not served from the cache", want)
		}
	}
	if _, ok := c.cacheFind([]string{"keymgmt:search"}); ok {
		t.Error("a scope the phone did not approve was served from the cache")
	}
	if _, ok := c.cacheFind([]string{"keymgmt:get", "keymgmt:del"}); ok {
		t.Error("a partial match was served")
	}

	c.cacheStore([]string{"keymgmt:del"}, fakeJWT(map[string]interface{}{"exp": time.Now().Add(-time.Minute).Unix(), "scope": "keymgmt:del"}))
	if _, ok := c.cacheFind([]string{"keymgmt:del"}); ok {
		t.Error("an expired token was served")
	}
}

func TestNoCacheScopesInsideAnArray(t *testing.T) {
	c := NewClient("https://hem.invalid", Config{NoCacheScopes: []string{"keymgmt:use:"}})
	jwt := fakeJWT(map[string]interface{}{"exp": time.Now().Add(time.Hour).Unix(), "scope": []string{"keymgmt:use:ab", "keymgmt:get"}})
	c.cacheStore([]string{"keymgmt:use:ab", "keymgmt:get"}, jwt)
	if _, ok := c.cacheFind([]string{"keymgmt:get"}); ok {
		t.Error("a token holding a no-cache scope was cached")
	}
}

func TestCheckScopes(t *testing.T) {
	ok := [][]string{{"keymgmt:get"}, {"keymgmt:use:00112233445566778899aabbccddeeff", "keymgmt:get"}}
	bad := [][]string{nil, {""}, {"a", "a"}, {"storage:disk0", "storage:disk1:ro"},
		{"1", "2", "3", "4", "5", "6", "7", "8", "9"}, {strings.Repeat("x", 45)}}
	for _, s := range ok {
		if err := checkScopes(s); err != nil {
			t.Errorf("%v: %v", s, err)
		}
	}
	for _, s := range bad {
		if err := checkScopes(s); err == nil {
			t.Errorf("%v accepted", s)
		}
	}
}

// AuthRemoteScopes sends the scope as an array, AuthRemote as a string: the
// device issues the token with the type that was asked for.
func TestAuthRemoteScopeWireType(t *testing.T) {
	var sent []interface{}
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/notify/session":
			io.WriteString(w, `{"epk":"x"}`)
		case "/api/auth/ext/request":
			sent = append(sent, body["scope"])
			io.WriteString(w, `{"authreq":"r"}`)
		case "/notify/event/new":
			io.WriteString(w, `{"eventid":"e1"}`)
		case "/notify/event/check/e1":
			io.WriteString(w, `{"authreply":"ok"}`)
		case "/api/auth/ext/token":
			io.WriteString(w, `{"token":"`+fakeJWT(map[string]interface{}{"exp": time.Now().Add(time.Hour).Unix(), "scope": "keymgmt:get"})+`"}`)
		}
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL
	c := NewClient(srvURL, Config{Broker: srvURL, DisableTokenCache: true})
	opts := RemoteOpts{PollInterval: time.Millisecond}
	if _, err := c.AuthRemote(context.Background(), "keymgmt:get", opts); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AuthRemoteScopes(context.Background(), []string{"keymgmt:use:ab", "keymgmt:get"}, opts); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 {
		t.Fatalf("sent = %v", sent)
	}
	if _, ok := sent[0].(string); !ok {
		t.Errorf("AuthRemote sent %T, want a string", sent[0])
	}
	if arr, ok := sent[1].([]interface{}); !ok || len(arr) != 2 || arr[0] != "keymgmt:use:ab" {
		t.Errorf("AuthRemoteScopes sent %v, want the array in order", sent[1])
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
	// Firmware 1.3 reads hkdf_ctx; a `ctx` field is ignored by the device and
	// would leave the key derived without any context.
	if rec.body["hkdf_ctx"] != b64("ENC-WG-PSK-v1") {
		t.Errorf("hkdf_ctx = %v", rec.body["hkdf_ctx"])
	}
	if _, ok := rec.body["ctx"]; ok {
		t.Error("ctx must not be sent: the device ignores it")
	}
	if _, ok := rec.body["hkdf_salt"]; ok {
		t.Error("hkdf_salt must be absent when Salt is unset")
	}
}

func TestCipherUnwrapCarriesSalt(t *testing.T) {
	c, rec := serve(t, `{"unwrapped":"`+b64("psk")+`"}`)
	_, err := c.CipherUnwrap(context.Background(), "tok", "kid1", []byte("w"),
		CryptoOpts{Alg: "AES256", ExtKID: "kid1", Ctx: []byte("c"), Salt: []byte("s")})
	if err != nil {
		t.Fatalf("CipherUnwrap: %v", err)
	}
	if rec.body["hkdf_ctx"] != b64("c") || rec.body["hkdf_salt"] != b64("s") {
		t.Errorf("body = %v", rec.body)
	}
}

// Firmware 1.3 answers a wrong MAC with 200 {"verified":false}. Treating any
// 200 as success, as this SDK once did, accepts every MAC.
func TestHmacVerifyReadsTheVerdict(t *testing.T) {
	for _, tc := range []struct {
		reply string
		ok    bool
	}{
		{`{"verified":true}`, true},
		{`{"verified":false}`, false},
		{`{}`, false},
		{``, false},
	} {
		c, rec := serve(t, tc.reply)
		err := c.HmacVerify(context.Background(), "tok", "kid1", []byte("m"), []byte("mac"),
			CryptoOpts{Alg: "SHA2-256", ExtKID: "kid1"})
		if rec.path != "/api/crypto/hmac/verify" {
			t.Fatalf("path = %s", rec.path)
		}
		if tc.ok && err != nil {
			t.Errorf("reply %q: %v", tc.reply, err)
		}
		if !tc.ok {
			he, isHem := err.(*HemError)
			if !isHem || he.Code != "not_verified" {
				t.Errorf("reply %q: err = %v, want not_verified", tc.reply, err)
			}
		}
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

	c.cacheStore([]string{"keymgmt:list"}, jwt)
	c.cacheStore([]string{"keymgmt:use:abcd"}, jwt)

	if _, ok := c.cacheFind([]string{"keymgmt:list"}); !ok {
		t.Error("keymgmt:list should be cached")
	}
	// A trailing ':' in NoCacheScopes matches by prefix, covering every KID.
	if _, ok := c.cacheFind([]string{"keymgmt:use:abcd"}); ok {
		t.Error("keymgmt:use:* must not be cached")
	}
}

func TestTokenCacheDropsExpired(t *testing.T) {
	c := NewClient("https://example.invalid", Config{})
	expired := "h." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":`+
		strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)+`}`)) + ".s"

	c.cacheStore([]string{"keymgmt:list"}, expired)
	if _, ok := c.cacheFind([]string{"keymgmt:list"}); ok {
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

func TestHemErrorShowsWhatTheDeviceSaid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"descr too long"}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, Config{})
	err := c.UpdateKey(context.Background(), "tok", "kid", "label", []byte("x"))
	if err == nil {
		t.Fatal("expected an error")
	}
	// "HTTP 400" alone gives a caller nothing to act on.
	if !strings.Contains(err.Error(), "descr too long") {
		t.Errorf("the device's explanation should reach the caller, got: %v", err)
	}
}

func TestHemErrorWithoutABodyIsUnchanged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, Config{})
	err := c.UpdateKey(context.Background(), "tok", "kid", "label", []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("got: %v", err)
	}
}
