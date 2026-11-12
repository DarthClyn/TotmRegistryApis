// Command pila-verifier checks credentials NOT issued by TOTM (PILA-issued eLCs and other PILA credentials) for the
// TOTM Trust API (POST /api/v1/pila/verify), with PILA's official Go SDK (github.com/pilacorp/go-credential-sdk):
// integrity (the signature), the issuer (signed by the issuer it names), expiry and revocation. Nothing is reimplemented.
//
// No DID is resolved here. The issuer's public key comes from:
//  1. PILA's verification context API (vcs[].didPublicKey), which the portal calls first and passes in (NDAKey
//     verifier guide 3.2, steps 6-8); or, when PILA has no key (issuer not registered),
//  2. the signature itself: an ES256K VC-JWT's signature gives back the signing key, and a did:nda DID is that key's
//     address, so the key is used only if its address equals the stated issuer's DID. Open, no registry needed.
//
// Either way PILA's SDK then checks the signature with that key. Issuer trust and live status are the verification
// context's answer, not this program's.
//
//	The API starts it as a child process (bin/pila-verifier, see src/pila.js and the Dockerfile).
//	go run .            (from pila-verifier/, listens on 127.0.0.1:4100) to run it on its own.
//
// Endpoints:
//
//	GET  /health   SDK version
//	POST /verify   {credential: <JSON object | JWT string>, issuerPublicKey?: <compressed secp256k1 hex from PILA>}
//
// Environment:
//
//	PORT                   default 4100
//	PILA_VERIFIER_TOKEN    optional shared secret; when set, callers must send X-Verifier-Token (set it when hosted)
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
	vm "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

const sdkVersion = "github.com/pilacorp/go-credential-sdk v1.13.1"

// p256MulticodecPrefix is varint(0x1200), the multicodec for a P-256 public key.
var p256MulticodecPrefix = []byte{0x80, 0x24}

func p256FromDIDKey(did string) (*ecdsa.PublicKey, string, error) {
	s := strings.TrimPrefix(did, "did:key:")
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	if !strings.HasPrefix(s, "z") {
		return nil, "", fmt.Errorf("did:key: expected base58btc multibase")
	}
	raw, err := base58.Decode(s[1:])
	if err != nil || len(raw) < 2 || raw[0] != p256MulticodecPrefix[0] || raw[1] != p256MulticodecPrefix[1] {
		return nil, "", fmt.Errorf("did:key: not a P-256 key")
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw[2:])
	if x == nil {
		return nil, "", fmt.Errorf("did:key: invalid P-256 point")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, s, nil
}

// keyResolver gives the SDK the issuer's key without any lookup: did:key describes its own key; for the credential's
// issuer, the key PILA's verification context returned (didPublicKey). Any other DID is refused, so a credential signed
// by a different DID than the one PILA vouched for fails the signature check.
type keyResolver struct {
	issuer string // the credential's issuer DID
	keyHex string // its public key from PILA's verification context, compressed secp256k1 hex
}

func (k keyResolver) ResolveDocument(_ context.Context, did string) (*vm.DIDDocument, error) {
	if strings.HasPrefix(did, "did:key:") {
		pub, mb, err := p256FromDIDKey(did)
		if err != nil {
			return nil, err
		}
		base := "did:key:" + mb
		entry, err := vm.NewP256VM(base, mb, pub)
		if err != nil {
			return nil, err
		}
		return vm.NewDIDDocument(base, entry), nil
	}
	if did == k.issuer && k.keyHex != "" {
		return vm.NewDIDDocument(did, vm.NewSecp256k1VM(did, "key-1", strings.TrimPrefix(k.keyHex, "0x"))), nil
	}
	if did != k.issuer {
		return nil, fmt.Errorf("signed by %s, not by the issuer %s", did, k.issuer)
	}
	return nil, fmt.Errorf("no public key for %s from PILA's verification context", did)
}

type server struct {
	token string // optional shared secret for callers
}

type check struct {
	Passed  bool   `json:"passed"`
	Error   string `json:"error,omitempty"`
	Skipped bool   `json:"skipped,omitempty"` // the check does not apply (e.g. no credentialStatus)
}

type verifyResponse struct {
	Format          string           `json:"format"` // json | jwt
	ID              string           `json:"id,omitempty"`
	Holder          string           `json:"holder,omitempty"` // credentialSubject.id
	Issuer          string           `json:"issuer,omitempty"`
	Types           []string         `json:"types,omitempty"`
	Subject         map[string]any   `json:"subject,omitempty"` // credentialSubject, for the result card
	ValidFrom       string           `json:"validFrom,omitempty"`
	ValidUntil      string           `json:"validUntil,omitempty"`
	IssuerSource    string           `json:"issuerSource,omitempty"`
	IssuerPublicKey string           `json:"issuerPublicKey,omitempty"` // the key the signature was checked with
	Checks          map[string]check `json:"checks"`                    // issuer, signature, expiration, revocation
	SDK             string           `json:"sdk"`
}

func main() {
	loadDotEnv(envOr("DOTENV_FILE", "../.env"))
	s := &server{token: os.Getenv("PILA_VERIFIER_TOKEN")}

	port := envOr("PORT", "4100")
	// Loopback on a developer machine; all interfaces when hosted (Railway/Vercel set these).
	host := envOr("HOST", "127.0.0.1")
	if os.Getenv("RAILWAY_ENVIRONMENT") != "" || os.Getenv("VERCEL") != "" {
		host = "0.0.0.0"
	}
	log.Printf("pila-verifier on %s:%s (%s, keys from PILA's verification context, token %v)", host, port, sdkVersion, s.token != "")
	log.Fatal(http.ListenAndServe(host+":"+port, logRequests(s.routes())))
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("POST /verify", s.authorised(s.verify))
	return mux
}

func (s *server) authorised(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Verifier-Token")), []byte(s.token)) != 1 {
			writeErr(w, 401, "missing or wrong X-Verifier-Token")
			return
		}
		next(w, r)
	}
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "sdk": sdkVersion, "issuerKeys": "PILA verification context (passed in)"})
}

func (s *server) verify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Credential      json.RawMessage `json:"credential"`
		IssuerPublicKey string          `json:"issuerPublicKey"` // from PILA's verification context (didPublicKey)
	}
	if err := decode(r, &body); err != nil || len(body.Credential) == 0 {
		writeErr(w, 400, "body must be {credential: <JSON object or JWT string>}")
		return
	}

	raw := []byte(body.Credential)
	format := "json"
	var asString string
	if json.Unmarshal(raw, &asString) == nil { // a JSON string: JWT / SD-JWT
		raw, format = []byte(strings.TrimSpace(asString)), "jwt"
	}

	cred, err := vc.ParseCredential(raw)
	if err != nil {
		writeErr(w, 400, "not a verifiable credential: "+err.Error())
		return
	}

	resp := verifyResponse{Format: format, Checks: map[string]check{}, SDK: sdkVersion}
	if contents, err := cred.GetContents(); err == nil {
		fillSummary(&resp, contents)
	}
	if format == "jwt" {
		fillFromJWTClaims(&resp, string(raw))
	}

	res := keyResolver{issuer: resp.Issuer, keyHex: strings.TrimSpace(body.IssuerPublicKey)}

	// 1. Issuer key: did:key carries its own; otherwise PILA's verification context, or the key the signature was made
	// with when its address is the stated issuer's DID. "issuer" passes when a key for the stated issuer is in hand;
	// the signature check below then proves that key signed this content.
	switch {
	case resp.Issuer == "":
		resp.Checks["issuer"] = check{Error: "credential has no issuer"}
	case strings.HasPrefix(resp.Issuer, "did:key:"):
		resp.Checks["issuer"] = check{Passed: true}
		resp.IssuerSource = "did:key (self-describing)"
	case res.keyHex != "":
		resp.Checks["issuer"] = check{Passed: true}
		resp.IssuerSource = "PILA verification context"
	case format == "jwt":
		key, err := keyFromSignature(string(raw), resp.Issuer)
		if err != nil {
			resp.Checks["issuer"] = check{Error: err.Error()}
		} else {
			res.keyHex = key
			resp.Checks["issuer"] = check{Passed: true}
			resp.IssuerSource = "signature (key address matches the issuer DID)"
		}
	default:
		resp.Checks["issuer"] = check{Error: "no public key for the issuer: not in PILA's verification context"}
	}
	resp.IssuerPublicKey = res.keyHex

	// 2. Signature (proof) through the SDK.
	if err := cred.Verify(vc.WithResolver(res)); err != nil {
		resp.Checks["signature"] = check{Error: err.Error()}
	} else {
		resp.Checks["signature"] = check{Passed: true}
	}

	// 3. Expiration.
	if err := cred.Verify(vc.WithResolver(res), vc.WithCheckExpiration()); err != nil && resp.Checks["signature"].Passed {
		resp.Checks["expiration"] = check{Error: err.Error()}
	} else {
		resp.Checks["expiration"] = check{Passed: true, Skipped: resp.ValidUntil == ""}
	}

	// 4. Revocation (status list), only if the credential declares a status.
	if cred.ExtractField("credentialStatus") == nil {
		resp.Checks["revocation"] = check{Passed: true, Skipped: true}
	} else if err := cred.Verify(vc.WithResolver(res), vc.WithCheckRevocation()); err != nil && resp.Checks["signature"].Passed {
		resp.Checks["revocation"] = check{Error: err.Error()}
	} else {
		resp.Checks["revocation"] = check{Passed: resp.Checks["signature"].Passed}
	}

	writeJSON(w, 200, resp)
}

func fillSummary(resp *verifyResponse, contents []byte) {
	var m map[string]any
	if json.Unmarshal(contents, &m) != nil {
		return
	}
	switch iss := m["issuer"].(type) {
	case string:
		resp.Issuer = iss
	case map[string]any:
		resp.Issuer, _ = iss["id"].(string)
	}
	if ts, ok := m["type"].([]any); ok {
		for _, t := range ts {
			if s, ok := t.(string); ok && s != "VerifiableCredential" {
				resp.Types = append(resp.Types, s)
			}
		}
	}
	resp.ID, _ = m["id"].(string)
	if resp.ID == "" {
		resp.ID, _ = m["jti"].(string)
	}
	resp.ValidFrom, _ = m["validFrom"].(string)
	resp.ValidUntil, _ = m["validUntil"].(string)
	subj, _ := m["credentialSubject"].(map[string]any)
	if subj == nil {
		if arr, ok := m["credentialSubject"].([]any); ok && len(arr) > 0 {
			subj, _ = arr[0].(map[string]any)
		}
	}
	if subj != nil {
		resp.Holder, _ = subj["id"].(string)
		resp.Subject = subj
		if len(resp.Types) == 0 {
			switch t := subj["type"].(type) {
			case string:
				resp.Types = append(resp.Types, t)
			case []any:
				for _, x := range t {
					if s, ok := x.(string); ok {
						resp.Types = append(resp.Types, s)
					}
				}
			}
		}
	}
}

// errNotIssuer: the signature was made with a key whose address is not the stated issuer's DID.
var errNotIssuer = errors.New("not signed by the stated issuer: the signing key's address is not the issuer DID")

// keyFromSignature recovers the key an ES256K VC-JWT was signed with and returns it (compressed hex) only if its
// address is the stated issuer's did:nda address. A changed payload recovers a different key, so it fails here too.
func keyFromSignature(token, issuerDID string) (string, error) {
	addr := issuerDID[strings.LastIndex(issuerDID, ":")+1:]
	if !strings.HasPrefix(issuerDID, "did:nda:") || len(addr) != 42 || !strings.HasPrefix(addr, "0x") {
		return "", fmt.Errorf("no public key for %s: not in PILA's verification context", issuerDID)
	}
	parts := strings.Split(strings.SplitN(token, "~", 2)[0], ".")
	if len(parts) != 3 {
		return "", errors.New("not a compact JWT")
	}
	var header struct{ Alg string }
	if h, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil || json.Unmarshal(h, &header) != nil {
		return "", errors.New("unreadable JWT header")
	}
	if header.Alg != "ES256K" {
		return "", fmt.Errorf("no public key for %s: not in PILA's verification context (%s keys cannot be recovered)", issuerDID, header.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return "", errors.New("unreadable ES256K signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	for v := byte(0); v < 2; v++ {
		pub, err := ethcrypto.SigToPub(digest[:], append(append([]byte{}, sig...), v))
		if err == nil && strings.EqualFold(ethcrypto.PubkeyToAddress(*pub).Hex(), addr) {
			return "0x" + hex.EncodeToString(ethcrypto.CompressPubkey(pub)), nil
		}
	}
	return "", errNotIssuer
}

// fillFromJWTClaims fills what the credential body leaves out from the JWT's registered claims, as the VC-JWT encoding
// allows (iss = issuer, jti = id, sub = holder, nbf / exp = validity). The body always wins when it has a value.
// Only the payload is read here; the signature is checked by the SDK.
func fillFromJWTClaims(resp *verifyResponse, token string) {
	parts := strings.Split(strings.SplitN(token, "~", 2)[0], ".")
	if len(parts) < 2 {
		return
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return
	}
	var c map[string]any
	if json.Unmarshal(payload, &c) != nil {
		return
	}
	str := func(k string) string { v, _ := c[k].(string); return v }
	when := func(k string) string {
		if n, ok := c[k].(float64); ok && n > 0 {
			return time.Unix(int64(n), 0).UTC().Format(time.RFC3339)
		}
		return ""
	}
	if resp.Issuer == "" {
		resp.Issuer = str("iss")
	}
	if resp.ID == "" {
		resp.ID = str("jti")
	}
	if resp.Holder == "" {
		resp.Holder = str("sub")
	}
	if resp.ValidFrom == "" {
		resp.ValidFrom = when("nbf")
	}
	if resp.ValidUntil == "" {
		resp.ValidUntil = when("exp")
	}
}

// --- helpers ---

// loadDotEnv reads PILA_* lines from the API's .env without overriding variables already set.
func loadDotEnv(file string) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return
	}
	n := 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.TrimSpace(strings.TrimPrefix(k, "export ")), strings.Trim(strings.TrimSpace(v), `"'`)
		if !ok || v == "" || !strings.HasPrefix(k, "PILA_") {
			continue
		}
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, v)
			n++
		}
	}
	log.Printf("loaded %d settings from %s", n, file)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func decode(r *http.Request, v any) error {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(nil, r.Body, 20<<20) // eLCs embed attachments + PDF
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return errors.New("invalid JSON body: " + err.Error())
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// logRequests logs each call with the caller's request ID (never the credential).
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s request=%s %s", r.Method, r.URL.Path, r.Header.Get("X-Request-Id"), time.Since(start).Round(time.Millisecond))
	})
}
