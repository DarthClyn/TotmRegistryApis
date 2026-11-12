package main

// NDAKey (PILA) public DID lookup: GET {PILA_NDAKEY_URL}/dids/{did}, no key needed
// ("NDAKey Integration Guide — Verifier" v2, 3.3.1). Used for did:nda issuers and holders:
//   - as the DID resolver for signature checks (PILA's SDK default resolver, api.ndadid.vn, can be
//     unreachable from partner networks);
//   - as the registry answer "is this DID registered with NDAKey, and as what (issuer / verifier)".
// The response holds one compressed secp256k1 public key; it becomes the DID document's #key-1,
// like DIDs made with PILA's didv2 SDK.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	vm "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

const defaultNDAKeyURL = "https://api-beta.ndakey.vn/service/api/v1"

// errNotRegistered: NDAKey answered, and the DID is not registered (404 E02).
var errNotRegistered = errors.New("DID not registered with NDAKey")

type ndakeyDID struct {
	DID       string `json:"did"`
	Type      string `json:"type"` // issuer | verifier | holder ...
	PublicKey string `json:"publicKey"`
}

type ndakeyClient struct {
	base  string
	http  *http.Client
	mu    sync.Mutex
	cache map[string]ndakeyCacheEntry
}

type ndakeyCacheEntry struct {
	did *ndakeyDID
	err error
	at  time.Time
}

func newNDAKeyClient(base string) *ndakeyClient {
	return &ndakeyClient{base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 10 * time.Second}, cache: map[string]ndakeyCacheEntry{}}
}

// lookup returns the registered DID, errNotRegistered, or a network/server error. Answers are cached
// for 5 minutes (not-registered and errors for 30 s) so one verification does not call NDAKey repeatedly.
func (c *ndakeyClient) lookup(ctx context.Context, did string) (*ndakeyDID, error) {
	c.mu.Lock()
	if e, ok := c.cache[did]; ok {
		ttl := 5 * time.Minute
		if e.err != nil {
			ttl = 30 * time.Second
		}
		if time.Since(e.at) < ttl {
			c.mu.Unlock()
			return e.did, e.err
		}
	}
	c.mu.Unlock()

	d, err := c.fetch(ctx, did)
	c.mu.Lock()
	c.cache[did] = ndakeyCacheEntry{did: d, err: err, at: time.Now()}
	c.mu.Unlock()
	return d, err
}

func (c *ndakeyClient) fetch(ctx context.Context, did string) (*ndakeyDID, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/dids/"+url.PathEscape(did), nil)
	if err != nil {
		return nil, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NDAKey not reachable: %w", err)
	}
	defer res.Body.Close()
	var body struct {
		Code    string     `json:"code"`
		Message string     `json:"message"`
		Error   string     `json:"error"`
		Data    *ndakeyDID `json:"data"`
	}
	_ = json.NewDecoder(res.Body).Decode(&body)
	switch {
	case res.StatusCode == http.StatusNotFound || body.Code == "E02":
		return nil, errNotRegistered
	case res.StatusCode != http.StatusOK || body.Data == nil:
		return nil, fmt.Errorf("NDAKey DID lookup failed: HTTP %d %s%s", res.StatusCode, body.Code, body.Error)
	}
	return body.Data, nil
}

// document builds the DID document the SDK verifies against: one secp256k1 key, #key-1.
func (d *ndakeyDID) document() (*vm.DIDDocument, error) {
	if d.PublicKey == "" {
		return nil, fmt.Errorf("NDAKey has no public key for %s", d.DID)
	}
	return vm.NewDIDDocument(d.DID, vm.NewSecp256k1VM(d.DID, "key-1", strings.TrimPrefix(d.PublicKey, "0x"))), nil
}

// registryInfo is what /verify reports about the issuer in NDAKey's registry.
type registryInfo struct {
	Checked    bool   `json:"checked"`          // NDAKey answered (or the DID cannot be registered, e.g. did:key)
	Registered bool   `json:"registered"`       // known to NDAKey
	Type       string `json:"type,omitempty"`   // issuer | verifier | ...
	Error      string `json:"error,omitempty"`  // why it could not be checked
	Source     string `json:"source,omitempty"` // "NDAKey"
}

func (c *ndakeyClient) registry(ctx context.Context, did string) *registryInfo {
	if c == nil {
		return &registryInfo{Error: "NDAKey lookup is switched off (PILA_NDAKEY_URL=off)"}
	}
	if !strings.HasPrefix(did, "did:nda:") {
		return &registryInfo{Checked: true, Source: "NDAKey"} // did:key etc. can never be NDAKey-registered
	}
	d, err := c.lookup(ctx, did)
	switch {
	case errors.Is(err, errNotRegistered):
		return &registryInfo{Checked: true, Source: "NDAKey"}
	case err != nil:
		return &registryInfo{Error: err.Error(), Source: "NDAKey"}
	}
	return &registryInfo{Checked: true, Registered: true, Type: d.Type, Source: "NDAKey"}
}
