// Demonstrate key and signature serialization round-trips.
//
// Run with: go run ./examples/serialize
package main

import (
	"fmt"

	"github.com/lattice-safe/falcon-go"
)

func main() {
	fmt.Println("=== FN-DSA Key & Signature Serialization ===")

	kp, err := falcon.Generate(9)
	if err != nil {
		panic(err)
	}
	message := []byte("Serialization round-trip test")

	// ── Key export / import ──────────────────────────────────────────────────────
	fmt.Println("\n📦 Exporting keys...")
	skBytes := kp.PrivateKey()
	pkBytes := kp.PublicKey()
	fmt.Printf("   Private key: %d bytes\n", len(skBytes))
	fmt.Printf("   Public key:  %d bytes\n", len(pkBytes))

	fmt.Println("\n📥 Restoring from (private_key, public_key)...")
	kp2, err := falcon.FromKeys(skBytes, pkBytes)
	if err != nil {
		panic(err)
	}
	if string(kp.PublicKey()) != string(kp2.PublicKey()) {
		panic("keys mismatch")
	}
	fmt.Println("   ✅ Keys match!")

	fmt.Println("\n📥 Restoring from private_key only...")
	kp3, err := falcon.FromPrivateKey(skBytes)
	if err != nil {
		panic(err)
	}
	if string(kp.PublicKey()) != string(kp3.PublicKey()) {
		panic("recomputed key mismatch")
	}
	fmt.Println("   ✅ Recomputed public key matches!")

	// ── Pure FN-DSA signature round-trip ────────────────────────────────────────
	fmt.Println("\n📦 Signing with DomainNone...")
	sig, err := kp.Sign(message, falcon.DomainNone())
	if err != nil {
		panic(err)
	}
	fmt.Printf("   Signature: %d bytes\n", sig.Len())
	sigBytes := sig.Bytes()
	sig2, err := falcon.FromSignatureBytes(sigBytes)
	if err != nil {
		panic(err)
	}
	if err := sig2.Verify(pkBytes, message, falcon.DomainNone()); err != nil {
		panic(err)
	}
	fmt.Println("   ✅ Pure FN-DSA round-trip successful!")

	// ── Context-string signature round-trip ──────────────────────────────────────
	fmt.Println("\n📦 Signing with DomainContext...")
	ctx, _ := falcon.DomainContext([]byte("my-protocol-v1"))
	sigCtx, err := kp.Sign(message, ctx)
	if err != nil {
		panic(err)
	}
	sigCtx2, err := falcon.FromSignatureBytes(sigCtx.Bytes())
	if err != nil {
		panic(err)
	}
	if err := sigCtx2.Verify(pkBytes, message, ctx); err != nil {
		panic(err)
	}
	fmt.Println("   ✅ Context FN-DSA round-trip successful!")

	// ── HashFN-DSA round-trip ────────────────────────────────────────────────────
	fmt.Println("\n📦 Signing with DomainPrehashed (SHA-256)...")
	ph, _ := falcon.DomainPrehashed(falcon.PreHashSHA256, []byte("my-protocol-v2"))
	sigPH, err := kp.Sign(message, ph)
	if err != nil {
		panic(err)
	}
	sigPH2, err := falcon.FromSignatureBytes(sigPH.Bytes())
	if err != nil {
		panic(err)
	}
	if err := sigPH2.Verify(pkBytes, message, ph); err != nil {
		panic(err)
	}
	fmt.Println("   ✅ HashFN-DSA SHA-256 round-trip successful!")
}
