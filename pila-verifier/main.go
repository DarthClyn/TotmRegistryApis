// Command pila-verifier checks credentials NOT issued by TOTM (PILA-issued eLCs and other PILA credentials) for the
// TOTM Trust API (POST /api/v1/pila/verify). It is a verification-only cut of the Orchestration Layer's pila-bridge:
//
//   - PILA's official Go SDK (github.com/pilacorp/go-credential-sdk) checks the signature, resolves the issuer DID
//     (NDAKey registry, then PILA's public DID resolver), expiry and revocation. Nothing is reimplemented here.
//
//   - NDAKey's verifier API (POST /vp/verification-context) adds what the SDK cannot know: whether the issuer is
//     trusted and the credential's live status. It needs our NDAKey verifier key (PILA_PARTNER_API_KEY).
//
//     The API starts it as a child process (bin/pila-verifier, see src/pila.js and the Dockerfile).
//     go run .            (from pila-verifier/, listens on 127.0.0.1:4100) to run it on its own.
//
// Endpoints:
//
//	GET  /health   resolver, NDAKey URL, whether the verifier key is set
//	POST /verify   {credential: <JSON object | JWT string>} -> SDK checks + NDAKey verification context
//
// Environment (read from ../.env, the API's .env, without overriding the shell):
//
//	PORT                   default 4100
//	PILA_DID_RESOLVER_URL  default https://api.ndadid.vn/api/v1/did (the SDK's public resolver)
//	PILA_NDAKEY_URL        default https://api-beta.ndakey.vn/service/api/v1 ("off" to skip NDAKey)
//	PILA_PARTNER_API_KEY   NDAKey verifier API key (SECRET); without it there is no verification context
//	PILA_VERIFIER_TOKEN    optional shared secret; when set, callers must send X-Verifier-Token (set it when hosted)
//	DOTENV_FILE            default ../.env
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mr-tron/base58"
	vm "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

const (
	defaultResolver = "https://api.ndadid.vn/api/v1/did"
	sdkVersion      = "github.com/pilacorp/go-credential-sdk v1.13.1"
)

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

// chainResolver: did:key resolves locally (self-describing); did:nda goes to NDAKey's registry first, then PILA's
// public resolver through the SDK. Same order as the pila-bridge, without its demo-bank fallback.
type chainResolver struct {
	http   *vm.HTTPResolver
	ndakey *ndakeyClient // nil when PILA_NDAKEY_URL=off
}

func (c chainResolver) ResolveDocument(ctx context.Context, did string) (*vm.DIDDocument, error) {
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
	if c.ndakey != nil && strings.HasPrefix(did, "did:nda:") {
		if d, err := c.ndakey.lookup(ctx, did); err == nil {
			return d.document()
		}
	}
	return c.http.ResolveDocument(ctx, did)
}

// issuerSource says where the issuer DID document came from.
func (c chainResolver) issuerSource(ctx context.Context, did string) string {
	if c.ndakey != nil && strings.HasPrefix(did, "did:nda:") {
		if d, err := c.ndakey.lookup(ctx, did); err == nil {
			return "NDAKey registry (" + d.Type + ")"
		}
	}
	if strings.HasPrefix(did, "did:key:") {
		return "did:key (self-describing, not a registered issuer)"
	}
	return "PILA DID resolver"
}

type server struct {
	resolverURL string
	resolver    chainResolver
	apiKey      string // NDAKey verifier key
	token       string // optional shared secret for callers
}

type check struct {
	Passed  bool   `json:"passed"`
	Error   string `json:"error,omitempty"`
	Skipped bool   `json:"skipped,omitempty"` // the check does not apply (e.g. no credentialStatus)
}

// ndakeyResult is NDAKey's verification context for this credential (or why there is none).
type ndakeyResult struct {
	Called          bool    `json:"called"`
	RequestID       string  `json:"requestId,omitempty"`
	Status          string  `json:"status,omitempty"` // active | revoked | expired | verified | not_found
	IsIssuerTrusted *bool   `json:"isIssuerTrusted,omitempty"`
	DIDPublicKey    *string `json:"didPublicKey,omitempty"`
	Error           string  `json:"error,omitempty"`   // the call failed
	Skipped         string  `json:"skipped,omitempty"` // why it was not called
}

type verifyResponse struct {
	Format       string           `json:"format"` // json | jwt
	ID           string           `json:"id,omitempty"`
	Holder       string           `json:"holder,omitempty"` // credentialSubject.id
	Issuer       string           `json:"issuer,omitempty"`
	Registry     *registryInfo    `json:"issuerRegistry,omitempty"`
	Types        []string         `json:"types,omitempty"`
	Subject      map[string]any   `json:"subject,omitempty"` // credentialSubject, for the result card
	ValidFrom    string           `json:"validFrom,omitempty"`
	ValidUntil   string           `json:"validUntil,omitempty"`
	IssuerSource string           `json:"issuerSource,omitempty"`
	Checks       map[string]check `json:"checks"` // issuer, signature, expiration, revocation
	NDAKey       ndakeyResult     `json:"ndakey"`
	SDK          string           `json:"sdk"`
}

func main() {
	loadDotEnv(envOr("DOTENV_FILE", "../.env"))
	resolverURL := envOr("PILA_DID_RESOLVER_URL", defaultResolver)
	vc.Init(resolverURL)

	s := &server{
		resolverURL: resolverURL,
		resolver:    chainResolver{http: vm.NewHTTPResolver(resolverURL), ndakey: ndakeyFromEnv()},
		apiKey:      os.Getenv("PILA_PARTNER_API_KEY"),
		token:       os.Getenv("PILA_VERIFIER_TOKEN"),
	}

	port := envOr("PORT", "4100")
	// Loopback on a developer machine; all interfaces when hosted (Railway/Vercel set these).
	host := envOr("HOST", "127.0.0.1")
	if os.Getenv("RAILWAY_ENVIRONMENT") != "" || os.Getenv("VERCEL") != "" {
		host = "0.0.0.0"
	}
	log.Printf("pila-verifier on %s:%s (resolver %s, NDAKey %s, verifier key %v, token %v)",
		host, port, resolverURL, ndakeyURL(), s.apiKey != "", s.token != "")
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
	writeJSON(w, 200, map[string]any{"ok": true, "resolver": s.resolverURL, "ndakey": ndakeyURL(), "verifierKey": s.apiKey != "", "sdk": sdkVersion})
}

func (s *server) verify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Credential json.RawMessage `json:"credential"`
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

	// 1. Issuer: can the issuer's DID be resolved?
	if resp.Issuer == "" {
		resp.Checks["issuer"] = check{Error: "credential has no issuer"}
	} else if _, err := s.resolver.ResolveDocument(r.Context(), resp.Issuer); err != nil {
		resp.Checks["issuer"] = check{Error: err.Error()}
	} else {
		resp.Checks["issuer"] = check{Passed: true}
		resp.IssuerSource = s.resolver.issuerSource(r.Context(), resp.Issuer)
	}
	if resp.Issuer != "" {
		resp.Registry = s.resolver.ndakey.registry(r.Context(), resp.Issuer)
	}

	// 2. Signature (proof) through the SDK.
	if err := cred.Verify(vc.WithResolver(s.resolver)); err != nil {
		resp.Checks["signature"] = check{Error: err.Error()}
	} else {
		resp.Checks["signature"] = check{Passed: true}
	}

	// 3. Expiration.
	if err := cred.Verify(vc.WithResolver(s.resolver), vc.WithCheckExpiration()); err != nil && resp.Checks["signature"].Passed {
		resp.Checks["expiration"] = check{Error: err.Error()}
	} else {
		resp.Checks["expiration"] = check{Passed: true, Skipped: resp.ValidUntil == ""}
	}

	// 4. Revocation (status list), only if the credential declares a status.
	if cred.ExtractField("credentialStatus") == nil {
		resp.Checks["revocation"] = check{Passed: true, Skipped: true}
	} else if err := cred.Verify(vc.WithResolver(s.resolver), vc.WithCheckRevocation()); err != nil && resp.Checks["signature"].Passed {
		resp.Checks["revocation"] = check{Error: err.Error()}
	} else {
		resp.Checks["revocation"] = check{Passed: resp.Checks["signature"].Passed}
	}

	// 5. NDAKey verification context: issuer trust + live status.
	resp.NDAKey = s.ndakeyContext(r.Context(), resp, r.Header.Get("X-Request-Id"))

	writeJSON(w, 200, resp)
}

func (s *server) ndakeyContext(ctx context.Context, resp verifyResponse, requestID string) ndakeyResult {
	switch {
	case s.resolver.ndakey == nil:
		return ndakeyResult{Skipped: "NDAKey is switched off (PILA_NDAKEY_URL=off)"}
	case s.apiKey == "":
		return ndakeyResult{Skipped: "no NDAKey verifier key configured (PILA_PARTNER_API_KEY)"}
	case resp.ID == "" || resp.Issuer == "":
		return ndakeyResult{Skipped: "the credential has no ID or issuer"}
	case resp.Holder == "":
		return ndakeyResult{Skipped: "the credential has no holder DID (credentialSubject.id), which NDAKey needs"}
	}
	out, err := s.resolver.ndakey.verificationContext(ctx, s.apiKey, resp.Holder, resp.ID, resp.Issuer, requestID)
	if err != nil {
		return ndakeyResult{Called: true, Error: err.Error()}
	}
	return *out
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

func ndakeyURL() string { return envOr("PILA_NDAKEY_URL", defaultNDAKeyURL) }

func ndakeyFromEnv() *ndakeyClient {
	if ndakeyURL() == "off" {
		return nil
	}
	return newNDAKeyClient(ndakeyURL())
}
