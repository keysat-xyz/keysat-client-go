// Offline verification example — `go run examples/offline_verify.go`
// from the package root. Replace the embedded pubkey + license key
// with your own.
package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/keysat-xyz/keysat-client-go"
)

const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=
-----END PUBLIC KEY-----`

const licenseKey = `LIC1-AIBW6RVE6YGS6SRIW2VD5D57N4UPBKVKVKVLXO6MZTO533XO53XO53QAAAAAAZKT6EAAAAAAABYT7MYA2NCGD73DC4G6MM5VVISRFTROCWWBECY4GJNM3LNGPQBOLFF2HM6QEA3QOJXQY3LVNR2GSLLEMV3GSY3F-QPSJIDYL6Y5TFCKXQ2SN43EDJIZIRJZCEROM2I4MJHODT6KO4KDPW6AJ3HMYJERYPD34CF2Z46PXPYFKSRZS7BDZKVKWE57UBJSTEBI`

func main() {
	pub, err := keysat.LoadPublicKeyPEM(publicKeyPEM)
	if err != nil {
		log.Fatalf("loading public key: %v", err)
	}
	// ParseAndVerifyAt checks the signature AND rejects an expired key in
	// one call. (Use ParseAndVerify if you'd rather inspect an expired key
	// than reject it.)
	payload, err := keysat.ParseAndVerifyAt(licenseKey, pub, time.Now().Unix())
	if errors.Is(err, keysat.ErrExpired) {
		log.Fatal("license expired")
	}
	if err != nil {
		log.Fatalf("license invalid: %v", err)
	}
	fmt.Printf("OK — version=%d trial=%v fingerprint_bound=%v entitlements=%v\n",
		payload.Version, payload.IsTrial(), payload.IsFingerprintBound(), payload.Entitlements)
}
