package main

import (
	"context"
	"strings"
	"testing"
)

// The issuer key only ever comes from PILA's verification context; nothing is looked up.
func TestKeyResolver(t *testing.T) {
	ctx := context.Background()
	issuer := "did:nda:testnet:0xissuer"
	key := "0x02b35b116329ad5ce29200000000000000000000000000000000000000000000"

	if _, err := (keyResolver{issuer: issuer, keyHex: key}).ResolveDocument(ctx, issuer); err != nil {
		t.Fatalf("issuer with a key from PILA: %v", err)
	}
	_, err := (keyResolver{issuer: issuer}).ResolveDocument(ctx, issuer)
	if err == nil || !strings.Contains(err.Error(), "no public key") {
		t.Fatalf("issuer without a key must fail, got %v", err)
	}
	_, err = (keyResolver{issuer: issuer, keyHex: key}).ResolveDocument(ctx, "did:nda:testnet:0xsomeoneelse")
	if err == nil || !strings.Contains(err.Error(), "not by the issuer") {
		t.Fatalf("a different signer must fail, got %v", err)
	}
}
