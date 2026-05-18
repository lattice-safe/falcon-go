// Sign a message and verify the signature — demonstrating all FIPS 206 domain modes.
//
// Run with: go run ./examples/sign_verify
package main

import (
	"fmt"

	"github.com/lattice-safe/falcon-go"
)

func main() {
	message := []byte("Hello, post-quantum world!")

	// ── Key generation ──────────────────────────────────────────────────────────
	fmt.Println("🔑 Generating FN-DSA-512 key pair...")
	kp, err := falcon.Generate(9)
	if err != nil {
		panic(err)
	}
	fmt.Printf("   Variant:    %s\n", kp.VariantName())
	fmt.Printf("   Public key: %d bytes\n", len(kp.PublicKey()))

	// ── Pure FN-DSA, no context (DomainNone) ────────────────────────────────────
	fmt.Println("\n── Pure FN-DSA (no context) ──")
	sig, err := kp.Sign(message, falcon.DomainNone())
	if err != nil {
		panic(err)
	}
	fmt.Printf("   Signature: %d bytes\n", sig.Len())
	if err := falcon.Verify(sig.Bytes(), kp.PublicKey(), message, falcon.DomainNone()); err != nil {
		panic(err)
	}
	fmt.Println("   ✅ Verified!")

	// ── Pure FN-DSA with protocol context (DomainContext) ───────────────────────
	fmt.Println("\n── Pure FN-DSA with context string ──")
	ctx, err := falcon.DomainContext([]byte("my-protocol-v1"))
	if err != nil {
		panic(err)
	}
	sigCtx, err := kp.Sign(message, ctx)
	if err != nil {
		panic(err)
	}
	if err := falcon.Verify(sigCtx.Bytes(), kp.PublicKey(), message, ctx); err != nil {
		panic(err)
	}
	fmt.Println("   ✅ Verified with context 'my-protocol-v1'!")

	// Cross-context rejection
	wrongCtx, _ := falcon.DomainContext([]byte("different-protocol"))
	if err := falcon.Verify(sigCtx.Bytes(), kp.PublicKey(), message, wrongCtx); err == nil {
		panic("expected cross-context rejection")
	}
	fmt.Println("   ✅ Correctly rejected by wrong context (cross-protocol protection)!")

	// ── HashFN-DSA with SHA-256 (DomainPrehashed) ───────────────────────────────
	fmt.Println("\n── HashFN-DSA (SHA-256 pre-hash) ──")
	ph256, err := falcon.DomainPrehashed(falcon.PreHashSHA256, []byte("my-protocol-v2"))
	if err != nil {
		panic(err)
	}
	sigPH, err := kp.Sign(message, ph256)
	if err != nil {
		panic(err)
	}
	fmt.Printf("   Signature: %d bytes\n", sigPH.Len())
	if err := falcon.Verify(sigPH.Bytes(), kp.PublicKey(), message, ph256); err != nil {
		panic(err)
	}
	fmt.Println("   ✅ HashFN-DSA SHA-256 verified!")

	// ── HashFN-DSA with SHA-512 ──────────────────────────────────────────────────
	fmt.Println("\n── HashFN-DSA (SHA-512 pre-hash) ──")
	ph512, err := falcon.DomainPrehashed(falcon.PreHashSHA512, nil)
	if err != nil {
		panic(err)
	}
	sigPH512, err := kp.Sign(message, ph512)
	if err != nil {
		panic(err)
	}
	if err := falcon.Verify(sigPH512.Bytes(), kp.PublicKey(), message, ph512); err != nil {
		panic(err)
	}
	fmt.Println("   ✅ HashFN-DSA SHA-512 verified!")

	// Cross-mode rejection: pure sig won't verify as HashFN-DSA
	if err := falcon.Verify(sig.Bytes(), kp.PublicKey(), message, ph256); err == nil {
		panic("expected cross-mode rejection")
	}
	fmt.Println("   ✅ Pure sig correctly rejected under Prehashed domain!")

	// ── Tamper detection ─────────────────────────────────────────────────────────
	fmt.Println("\n── Tamper detection ──")
	err = falcon.Verify(sig.Bytes(), kp.PublicKey(), []byte("wrong message"), falcon.DomainNone())
	if err == nil {
		panic("expected tamper rejection")
	}
	fmt.Printf("   ✅ Wrong-message correctly rejected: %v\n", err)
}
