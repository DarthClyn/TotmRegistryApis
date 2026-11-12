package main

// NDAKey verifier API: the verification context for a presented credential
// ("NDAKey Integration Guide — Verifier" v2, 3.3.2). POST {PILA_NDAKEY_URL}/vp/verification-context with our verifier
// key (X-Api-Key, server to server only). NDAKey answers, per credential, the issuer's public key, whether the issuer
// is trusted and the credential's live status. Signatures are never checked here: PILA's SDK does that in main.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type vcContext struct {
	VCID            string  `json:"vcid"`
	DIDPublicKey    *string `json:"didPublicKey"`
	IsIssuerTrusted bool    `json:"isIssuerTrusted"`
	Status          string  `json:"status"`
}

func (c *ndakeyClient) verificationContext(ctx context.Context, apiKey, holderDID, vcID, issuerDID, requestID string) (*ndakeyResult, error) {
	body, _ := json.Marshal(map[string]any{
		"holderDid": holderDID,
		"vcIds":     []map[string]string{{"vcId": vcID, "issuerDid": issuerDID}},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/vp/verification-context", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", apiKey)
	if requestID != "" {
		req.Header.Set("X-Request-Id", requestID)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NDAKey not reachable: %w", err)
	}
	defer res.Body.Close()
	var out struct {
		Code  string `json:"code"`
		Error string `json:"error"`
		Data  *struct {
			RequestID string      `json:"requestId"`
			VCs       []vcContext `json:"vcs"`
		} `json:"data"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode != http.StatusOK || out.Data == nil {
		return nil, fmt.Errorf("NDAKey verification context: HTTP %d %s %s", res.StatusCode, out.Code, out.Error)
	}
	if len(out.Data.VCs) == 0 {
		return nil, fmt.Errorf("NDAKey verification context: no answer for this credential")
	}
	v := out.Data.VCs[0]
	for _, x := range out.Data.VCs {
		if x.VCID == vcID {
			v = x
		}
	}
	rid := out.Data.RequestID
	if rid == "" { // the live API sends it as a header only
		rid = res.Header.Get("X-Request-Id")
	}
	trusted := v.IsIssuerTrusted
	return &ndakeyResult{Called: true, RequestID: rid, Status: v.Status, IsIssuerTrusted: &trusted, DIDPublicKey: v.DIDPublicKey}, nil
}
