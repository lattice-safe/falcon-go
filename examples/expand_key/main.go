// Demonstrate the ExpandedKey API for amortized multi-signature workloads.
//
// Run with: go run ./examples/expand_key
package main

import (
	"fmt"

	"github.com/lattice-safe/falcon-go"
)

func main() {
	messages := [][]byte{
		[]byte("First document to sign"),
		[]byte("Second document to sign"),
		[]byte("Third document to sign — no re-expansion needed"),
	}

	// ── Generate key pair ────────────────────────────────────────────────────────
	fmt.Println("🔑 Generating FN-DSA-512 key pair...")
	kp, err := falcon.Generate(9)
	if err != nil {
		panic(err)
	}
	fmt.Printf("   Variant: %s\n", kp.VariantName())

	// ── Expand once ──────────────────────────────────────────────────────────────
	fmt.Println("\n🌲 Expanding private key into signing handle...")
	ek, err := kp.Expand()
	if err != nil {
		panic(err)
	}
	fmt.Printf("   Public key same as kp: %v\n", string(ek.PublicKey()) == string(kp.PublicKey()))
	fmt.Printf("   logn = %d\n", ek.LogN())

	// ── Sign multiple messages — no re-expansion ─────────────────────────────────
	fmt.Println("\n✍️  Signing three messages with the expanded key...")
	for i, msg := range messages {
		sig, err := ek.Sign(msg, falcon.DomainNone())
		if err != nil {
			panic(err)
		}
		if err := falcon.Verify(sig.Bytes(), ek.PublicKey(), msg, falcon.DomainNone()); err != nil {
			panic(err)
		}
		fmt.Printf("   [%d/3] ✅ Signed and verified (%d bytes)\n", i+1, sig.Len())
	}

	// ── Works with all domain separation modes ───────────────────────────────────
	fmt.Println("\n── HashFN-DSA with expanded key ──")
	ph, err := falcon.DomainPrehashed(falcon.PreHashSHA256, []byte("my-protocol-v1"))
	if err != nil {
		panic(err)
	}
	sigPH, err := ek.Sign(messages[0], ph)
	if err != nil {
		panic(err)
	}
	if err := falcon.Verify(sigPH.Bytes(), ek.PublicKey(), messages[0], ph); err != nil {
		panic(err)
	}
	fmt.Println("   ✅ HashFN-DSA SHA-256 verified with expanded key!")

	// ── Deterministic signing ────────────────────────────────────────────────────
	fmt.Println("\n── Deterministic signing with expanded key ──")
	sig, err := ek.SignDeterministic(messages[1], []byte("deterministic-seed"), falcon.DomainNone())
	if err != nil {
		panic(err)
	}
	if err := falcon.Verify(sig.Bytes(), ek.PublicKey(), messages[1], falcon.DomainNone()); err != nil {
		panic(err)
	}
	fmt.Println("   ✅ Deterministic signature verified!")
	fmt.Println("\n🎉 Expanded-key demo complete.")
}
