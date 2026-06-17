// Package keysat is the Go SDK for Keysat — a self-hosted, Bitcoin-paid
// software licensing service. It parses and verifies LIC1-format
// license keys against an Ed25519 public key, and optionally validates
// them online against a running Keysat daemon.
//
// # Wire format
//
// A key string looks like LIC1-<payload_b32>-<signature_b32>. Both halves
// are RFC 4648 base32 (uppercase, no padding) of the raw bytes.
//
// # Versions
//
// v1 is the legacy 74-byte fixed payload. New keys are issued as v2,
// which adds expires_at and variable-length entitlement slugs. Both
// versions are accepted; clients should treat v1 keys as perpetual
// with no entitlements.
//
// Do not edit one SDK without the others — the wire format is
// crosscheck-tested across all four implementations (the daemon,
// the Rust SDK, the TS SDK, and this one) using the shared
// vectors at tests/crosscheck/vector.json in the parent keysat
// repo.
package keysat

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Wire-format identifiers. v1 is legacy; new keys are issued as v2.
const (
	KeyPrefix   = "LIC1"
	KeyVersionV1 byte = 1
	KeyVersionV2 byte = 2
)

// Flag bits in the payload's second byte.
const (
	FlagFingerprintBound byte = 0b0000_0001
	FlagTrial            byte = 0b0000_0010
)

// Fixed lengths.
const (
	signatureLen     = 64
	payloadV1Len     = 74
	payloadV2HeadLen = 83
)

// b32 is RFC 4648 base32, uppercase, no padding — the alphabet used by
// every Keysat SDK and the daemon. Defined once so callers can't pick
// a slightly-different variant by mistake.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// LicensePayload is the parsed contents of a license key, version-
// independent. v1 keys parse with ExpiresAt=0 and Entitlements=nil so
// callers don't need to branch on Version.
type LicensePayload struct {
	Version         byte
	Flags           byte
	ProductID       [16]byte
	LicenseID       [16]byte
	IssuedAt        int64
	ExpiresAt       int64 // 0 = perpetual; always 0 on v1
	FingerprintHash [32]byte
	Entitlements    []string
}

// IsFingerprintBound reports whether the key was issued bound to a
// machine fingerprint hash (FlagFingerprintBound is set).
func (p *LicensePayload) IsFingerprintBound() bool {
	return p.Flags&FlagFingerprintBound != 0
}

// IsTrial reports whether the key represents a trial (FlagTrial is set).
func (p *LicensePayload) IsTrial() bool {
	return p.Flags&FlagTrial != 0
}

// IsExpiredAt reports whether the key has expired at the given Unix
// time. Perpetual keys (ExpiresAt == 0) always return false.
func (p *LicensePayload) IsExpiredAt(nowUnix int64) bool {
	return p.ExpiresAt != 0 && nowUnix >= p.ExpiresAt
}

// HasEntitlement reports whether the key grants the named entitlement.
// Comparison is case-sensitive; callers should pick a canonical casing.
func (p *LicensePayload) HasEntitlement(slug string) bool {
	for _, e := range p.Entitlements {
		if e == slug {
			return true
		}
	}
	return false
}

// HashFingerprint computes SHA-256 of the supplied raw fingerprint
// string, returning the 32 raw hash bytes. Used to compare a
// machine's fingerprint against a license's bound hash without ever
// transmitting the raw fingerprint to the daemon.
//
// Mirrors keysat::crypto::hash_fingerprint in the daemon, so the
// crosscheck vectors round-trip identically.
func HashFingerprint(rawFingerprint string) [32]byte {
	return sha256.Sum256([]byte(rawFingerprint))
}

// ParseKey decodes a LIC1-format key string into its payload, the raw
// signature bytes, and the canonical signed-bytes prefix that the
// signature covers. Callers typically pass (payload, sig, signed) to
// Verify next.
//
// Returns an error wrapping ErrBadFormat for any structural problem
// (wrong prefix, bad base32, truncated payload, unknown version).
func ParseKey(s string) (LicensePayload, []byte, []byte, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 3 {
		return LicensePayload{}, nil, nil, fmt.Errorf("%w: expected LIC1-<payload>-<sig>", ErrBadFormat)
	}
	if parts[0] != KeyPrefix {
		return LicensePayload{}, nil, nil, fmt.Errorf("%w: prefix is %q, expected %q", ErrBadFormat, parts[0], KeyPrefix)
	}
	payloadBytes, err := b32.DecodeString(parts[1])
	if err != nil {
		return LicensePayload{}, nil, nil, fmt.Errorf("%w: payload base32: %v", ErrBadFormat, err)
	}
	sigBytes, err := b32.DecodeString(parts[2])
	if err != nil {
		return LicensePayload{}, nil, nil, fmt.Errorf("%w: signature base32: %v", ErrBadFormat, err)
	}
	if len(sigBytes) != signatureLen {
		return LicensePayload{}, nil, nil, fmt.Errorf("%w: signature is %d bytes, expected %d", ErrBadFormat, len(sigBytes), signatureLen)
	}

	if len(payloadBytes) < 1 {
		return LicensePayload{}, nil, nil, fmt.Errorf("%w: empty payload", ErrBadFormat)
	}
	version := payloadBytes[0]

	var p LicensePayload
	switch version {
	case KeyVersionV1:
		if len(payloadBytes) != payloadV1Len {
			return LicensePayload{}, nil, nil, fmt.Errorf("%w: v1 payload is %d bytes, expected %d", ErrBadFormat, len(payloadBytes), payloadV1Len)
		}
		p = LicensePayload{
			Version:   KeyVersionV1,
			Flags:     payloadBytes[1],
			IssuedAt:  int64(binary.BigEndian.Uint64(payloadBytes[34:42])),
			ExpiresAt: 0,
		}
		copy(p.ProductID[:], payloadBytes[2:18])
		copy(p.LicenseID[:], payloadBytes[18:34])
		copy(p.FingerprintHash[:], payloadBytes[42:74])

	case KeyVersionV2:
		if len(payloadBytes) < payloadV2HeadLen {
			return LicensePayload{}, nil, nil, fmt.Errorf("%w: v2 payload is %d bytes, need at least %d", ErrBadFormat, len(payloadBytes), payloadV2HeadLen)
		}
		p = LicensePayload{
			Version:   KeyVersionV2,
			Flags:     payloadBytes[1],
			IssuedAt:  int64(binary.BigEndian.Uint64(payloadBytes[34:42])),
			ExpiresAt: int64(binary.BigEndian.Uint64(payloadBytes[42:50])),
		}
		copy(p.ProductID[:], payloadBytes[2:18])
		copy(p.LicenseID[:], payloadBytes[18:34])
		copy(p.FingerprintHash[:], payloadBytes[50:82])

		// Entitlement count + variable-length tail.
		numEnts := int(payloadBytes[82])
		off := payloadV2HeadLen
		for i := 0; i < numEnts; i++ {
			if off >= len(payloadBytes) {
				return LicensePayload{}, nil, nil, fmt.Errorf("%w: entitlement count %d but truncated tail", ErrBadFormat, numEnts)
			}
			slugLen := int(payloadBytes[off])
			off++
			if off+slugLen > len(payloadBytes) {
				return LicensePayload{}, nil, nil, fmt.Errorf("%w: entitlement %d declares %d bytes but only %d remain", ErrBadFormat, i, slugLen, len(payloadBytes)-off)
			}
			p.Entitlements = append(p.Entitlements, string(payloadBytes[off:off+slugLen]))
			off += slugLen
		}
		// We don't error on trailing bytes: a future SDK might append fields,
		// and this one should still parse the prefix it understands.

	default:
		return LicensePayload{}, nil, nil, fmt.Errorf("%w: unknown version %d", ErrBadFormat, version)
	}

	return p, sigBytes, payloadBytes, nil
}

// Verify checks that the signature was made over signedBytes by the
// holder of the private key corresponding to pub. signedBytes is what
// ParseKey returns as its third value — the raw payload bytes BEFORE
// base32 decoding (Ed25519 signs raw bytes, not their base32 form).
//
// Returns nil if the signature is valid, ErrBadSignature otherwise.
func Verify(pub ed25519.PublicKey, signedBytes, signature []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key is %d bytes, expected %d", ErrBadSignature, len(pub), ed25519.PublicKeySize)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes, expected %d", ErrBadSignature, len(signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, signedBytes, signature) {
		return ErrBadSignature
	}
	return nil
}

// ParseAndVerify is a convenience wrapper around ParseKey + Verify
// that returns the parsed payload only when the signature is valid.
// Most application code should call this rather than the lower-level
// pieces.
func ParseAndVerify(keyString string, pub ed25519.PublicKey) (LicensePayload, error) {
	payload, sig, signed, err := ParseKey(keyString)
	if err != nil {
		return LicensePayload{}, err
	}
	if err := Verify(pub, signed, sig); err != nil {
		return LicensePayload{}, err
	}
	return payload, nil
}

// LoadPublicKeyPEM parses a PEM-encoded Ed25519 public key (the format
// the daemon emits via /v1/issuer/public-key and embeds in operator-
// distributed SDKs). Returns the key ready to pass to Verify or
// ParseAndVerify.
func LoadPublicKeyPEM(pemData string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("expected 'PUBLIC KEY' PEM block, got %q", block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("PEM does not contain an Ed25519 key (got %T)", pub)
	}
	return ed, nil
}

// Sentinel error values. Wrap with fmt.Errorf("%w: ...") to add
// context; check with errors.Is.
var (
	// ErrBadFormat is returned when a key string is structurally
	// invalid — wrong prefix, bad base32, truncated payload, etc.
	ErrBadFormat = errors.New("bad_format")
	// ErrBadSignature is returned when the parsed signature does not
	// match the payload + public key.
	ErrBadSignature = errors.New("bad_signature")
)
