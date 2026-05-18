// Generate FN-DSA key pairs (512 and 1024) and inspect sizes / round-trip.
//
// Run with: go run ./examples/keygen
package main

import (
	"fmt"

	"github.com/lattice-safe/falcon-go"
)

func main() {
	for _, logn := range []uint{9, 10} {
		variant := "FN-DSA-512"
		if logn == 10 {
			variant = "FN-DSA-1024"
		}
		fmt.Printf("🔑 Generating %s key pair...\n", variant)
		kp, err := falcon.Generate(logn)
		if err != nil {
			panic(err)
		}

		fmt.Printf("  Variant:     %s\n", kp.VariantName())
		fmt.Printf("  Private key: %d bytes\n", len(kp.PrivateKey()))
		fmt.Printf("  Public key:  %d bytes\n", len(kp.PublicKey()))
		fmt.Printf("  Private key (first 16 bytes): %x\n", kp.PrivateKey()[:16])
		fmt.Printf("  Public key  (first 16 bytes): %x\n", kp.PublicKey()[:16])

		// Reconstruct from private key only
		restored, err := falcon.FromPrivateKey(kp.PrivateKey())
		if err != nil {
			panic(err)
		}
		if string(kp.PublicKey()) != string(restored.PublicKey()) {
			panic("public key mismatch after restore")
		}
		fmt.Printf("  ✅ Public key reconstructed from private key — match!\n\n")
	}
}
