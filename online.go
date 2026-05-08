// Online validation against a running Keysat daemon. Use this when
// you want to honour revocation, machine-cap enforcement, or
// fingerprint binding — the offline ParseAndVerify path can't see
// post-issuance state changes.
//
// Most software calls Validate at startup (or first use), trusts
// the result for some grace period, and falls back to offline
// verification if the daemon is unreachable.

package keysat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to a running Keysat daemon's public API. Construct
// with NewClient.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient returns a Client pointed at the daemon at baseURL with a
// 10-second default HTTP timeout. Pass a nil http.Client to use the
// default; pass your own to customise (proxy, custom transport, etc.).
func NewClient(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    httpClient,
	}
}

// ValidateRequest is the body of POST /v1/validate. Only Key is
// required; the rest fine-tune the validation.
type ValidateRequest struct {
	Key string `json:"key"`
	// ProductSlug, when non-empty, makes the daemon reject keys
	// issued for a different product even if otherwise valid.
	ProductSlug string `json:"product_slug,omitempty"`
	// Fingerprint, when non-empty, the first successful validation
	// binds this fingerprint to the license row; later validations
	// succeed only if it matches. SHA-256 hash is computed
	// daemon-side, so pass the raw value (machine UUID, etc.).
	Fingerprint string `json:"fingerprint,omitempty"`
	// Hostname is an optional human-friendly label stored on the
	// machines row.
	Hostname string `json:"hostname,omitempty"`
	// Platform is an optional descriptor like "linux-x64",
	// "darwin-arm64", "win-x64".
	Platform string `json:"platform,omitempty"`
}

// ValidateResponse is the daemon's reply. HTTP is always 200; the
// boolean OK + machine-readable Reason field signal success/failure.
type ValidateResponse struct {
	OK             bool     `json:"ok"`
	Reason         string   `json:"reason,omitempty"`
	LicenseID      string   `json:"license_id,omitempty"`
	ProductID      string   `json:"product_id,omitempty"`
	ProductSlug    string   `json:"product_slug,omitempty"`
	IssuedAt       string   `json:"issued_at,omitempty"`
	ExpiresAt      string   `json:"expires_at,omitempty"`
	GraceUntil     string   `json:"grace_until,omitempty"`
	InGracePeriod  *bool    `json:"in_grace_period,omitempty"`
	IsTrial        *bool    `json:"is_trial,omitempty"`
	Entitlements   []string `json:"entitlements,omitempty"`
	Status         string   `json:"status,omitempty"`
	MachineID      string   `json:"machine_id,omitempty"`
	MaxMachines    *int64   `json:"max_machines,omitempty"`
}

// Validate calls POST /v1/validate. The daemon returns 200 in all
// cases; structural HTTP / JSON errors are surfaced here, license
// failures are conveyed via ValidateResponse.OK + Reason. Inspect
// resp.OK before trusting the rest of the fields.
func (c *Client) Validate(ctx context.Context, req ValidateRequest) (ValidateResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return ValidateResponse{}, fmt.Errorf("marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/v1/validate", bytes.NewReader(body))
	if err != nil {
		return ValidateResponse{}, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("content-type", "application/json")

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return ValidateResponse{}, fmt.Errorf("validate request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ValidateResponse{}, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return ValidateResponse{}, fmt.Errorf("daemon returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var out ValidateResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return ValidateResponse{}, fmt.Errorf("decode response: %w (body=%s)", err, string(respBody))
	}
	return out, nil
}

// PublicKey fetches the daemon's PEM-encoded Ed25519 public key from
// /v1/pubkey. Useful for SDK consumers who want to verify offline
// against a daemon they trust to publish the key over HTTPS.
//
// Production deployments should embed the key at build time rather
// than fetching it; this function is primarily for development
// convenience.
func (c *Client) PublicKey(ctx context.Context) (string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/pubkey", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("fetch pubkey: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("daemon returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	// /v1/pubkey returns JSON like {"public_key_pem": "..."}.
	var wrap struct {
		PublicKeyPEM string `json:"public_key_pem"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		// If it's already raw PEM, return as-is — older daemons did
		// this and we want to stay compatible.
		if strings.Contains(string(body), "BEGIN PUBLIC KEY") {
			return string(body), nil
		}
		return "", fmt.Errorf("decode pubkey response: %w", err)
	}
	return wrap.PublicKeyPEM, nil
}
