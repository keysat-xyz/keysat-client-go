# keysat-client-go

Go SDK for [Keysat](https://keysat.xyz) — a Bitcoin-native self-hosted software licensing service.

Verifies LIC1-format license keys offline against an Ed25519 public key, and optionally validates them online against a running Keysat daemon.

## Install

```bash
go get github.com/keysat-xyz/keysat-client-go
```

Stdlib only — no third-party dependencies.

## Offline verification

```go
package main

import (
    "errors"
    "fmt"
    "log"
    "time"

    "github.com/keysat-xyz/keysat-client-go"
)

// Embed the daemon's PEM public key at build time. Get it from your
// Keysat admin UI or `curl https://your-keysat.example/v1/pubkey`.
const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA...
-----END PUBLIC KEY-----`

func main() {
    pub, err := keysat.LoadPublicKeyPEM(publicKeyPEM)
    if err != nil { log.Fatal(err) }

    licenseKey := readKeyFromUserConfig() // however your app stores it

    // Checks the signature and rejects an expired key in one call.
    payload, err := keysat.ParseAndVerifyAt(licenseKey, pub, time.Now().Unix())
    if err != nil {
        if errors.Is(err, keysat.ErrExpired) { log.Fatal("license expired") }
        log.Fatalf("license invalid: %v", err)
    }

    if !payload.HasEntitlement("pro") {
        log.Fatal("license does not include 'pro' tier")
    }
    fmt.Println("license OK")
}
```

## Online validation (revocation, fingerprint binding, machine cap)

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

c := keysat.NewClient("https://licensing.example.com", nil)
resp, err := c.Validate(ctx, keysat.ValidateRequest{
    Key:         licenseKey,
    ProductSlug: "myapp",
    Fingerprint: machineUUID,
})
if err != nil { log.Fatalf("daemon unreachable: %v", err) }
if !resp.OK {
    log.Fatalf("license rejected: %s", resp.Reason)
}
```

`Validate` returns HTTP 200 in all cases; license failures are conveyed via `resp.OK + resp.Reason` (`bad_signature`, `revoked`, `expired`, `too_many_machines`, etc.).

## Fingerprint binding

When a key is fingerprint-bound, the daemon's first successful online validation pins the machine's fingerprint hash to the license row. Subsequent validations from a different machine fail with `fingerprint_mismatch`.

The SDK exposes `keysat.HashFingerprint` if you need to compute the hash yourself (e.g., to compare against a key's `FingerprintHash` field offline):

```go
h := keysat.HashFingerprint(machineUUID)
if h != payload.FingerprintHash {
    log.Fatal("license does not belong to this machine")
}
```

## Wire format compatibility

Every SDK + the daemon agree on the LIC1 wire format. Crosscheck tests in this package run against the shared `tests/crosscheck/vector.json` (alongside the daemon repo) — three independently-signed fixtures (v1 legacy, v2 trial with entitlements, v2 perpetual unbound) parse to the same field values across Rust, TypeScript, Python, and Go.

When fetched standalone via `go get`, the crosscheck test skips gracefully (the vector file isn't bundled into the Go module). The crosscheck only runs from the parent `keysat/` workspace.

## API stability

This SDK is alpha; the wire format is stable against Keysat v0.2. The LIC1 format itself won't break compatibility — license keys issued by any Keysat daemon will keep parsing in any future SDK. The Go API surface (function names, struct fields) may settle further before v1.0; nothing here is wildly out of line with idiomatic Go but expect minor tweaks.

## License

MIT — see `LICENSE`.
