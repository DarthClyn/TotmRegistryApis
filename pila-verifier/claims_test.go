package main

import "testing"

// A VC-JWT whose credential body has no issuer, id, holder or dates: they come from the JWT claims.
const claimsOnlyJWT = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJkaWQ6bmRhOnRlc3RuZXQ6MHhpc3N1ZXIiLCJqdGkiOiJ1cm46dXVpZDpjbGFpbXMtaWQiLCJzdWIiOiJkaWQ6d2ViOmhvbGRlci5leGFtcGxlIiwibmJmIjoxNzk0MzkzNzEzLCJleHAiOjE4MDY0NTEyMDAsInZjIjp7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJFbGVjdHJvbmljTGV0dGVyT2ZDcmVkaXQiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsibGNOdW1iZXIiOiJMQy0xIn19fQ.c2ln"

func TestFillFromJWTClaims(t *testing.T) {
	r := verifyResponse{}
	fillFromJWTClaims(&r, claimsOnlyJWT)
	want := map[string][2]string{
		"issuer": {r.Issuer, "did:nda:testnet:0xissuer"},
		"id":     {r.ID, "urn:uuid:claims-id"},
		"holder": {r.Holder, "did:web:holder.example"},
		"from":   {r.ValidFrom, "2026-11-11T10:41:53Z"},
		"until":  {r.ValidUntil, "2027-03-31T00:00:00Z"},
	}
	for name, v := range want {
		if v[0] != v[1] {
			t.Errorf("%s = %q, want %q", name, v[0], v[1])
		}
	}
}

func TestCredentialBodyWins(t *testing.T) {
	r := verifyResponse{Issuer: "did:body", ID: "urn:body", Holder: "did:holder", ValidFrom: "2026-01-01T00:00:00Z"}
	fillFromJWTClaims(&r, claimsOnlyJWT)
	if r.Issuer != "did:body" || r.ID != "urn:body" || r.Holder != "did:holder" || r.ValidFrom != "2026-01-01T00:00:00Z" {
		t.Errorf("claims overwrote the credential body: %+v", r)
	}
	if r.ValidUntil != "2027-03-31T00:00:00Z" {
		t.Errorf("missing validUntil not filled from exp: %q", r.ValidUntil)
	}
}

func TestNotAJWT(t *testing.T) {
	r := verifyResponse{}
	fillFromJWTClaims(&r, "not-a-token")
	if r.Issuer != "" || r.ID != "" {
		t.Errorf("filled from garbage: %+v", r)
	}
}
