package falcon

import "testing"

// ── FN-DSA-512 Benchmarks ───────────────────────────────────────────────────

func BenchmarkKeygen512(b *testing.B) {
	seed := []byte("bench-keygen-seed-512")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := GenerateDeterministic(seed, 9); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign512_None(b *testing.B) {
	kp, _ := GenerateDeterministic([]byte("bench-key-512"), 9)
	msg := []byte("Benchmark message for FN-DSA-512")
	seed := []byte("bench-sign-seed")
	domain := DomainNone()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := kp.SignDeterministic(msg, seed, domain); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign512_Context(b *testing.B) {
	kp, _ := GenerateDeterministic([]byte("bench-key-512"), 9)
	msg := []byte("Benchmark message for FN-DSA-512")
	seed := []byte("bench-sign-seed")
	domain, _ := DomainContext([]byte("bench-protocol-v1"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := kp.SignDeterministic(msg, seed, domain); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign512_SHA256(b *testing.B) {
	kp, _ := GenerateDeterministic([]byte("bench-key-512"), 9)
	msg := []byte("Benchmark message for FN-DSA-512")
	seed := []byte("bench-sign-seed")
	domain, _ := DomainPrehashed(PreHashSHA256, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := kp.SignDeterministic(msg, seed, domain); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign512_SHA512(b *testing.B) {
	kp, _ := GenerateDeterministic([]byte("bench-key-512"), 9)
	msg := []byte("Benchmark message for FN-DSA-512")
	seed := []byte("bench-sign-seed")
	domain, _ := DomainPrehashed(PreHashSHA512, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := kp.SignDeterministic(msg, seed, domain); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify512_None(b *testing.B) {
	kp, _ := GenerateDeterministic([]byte("bench-key-512"), 9)
	msg := []byte("Benchmark message for FN-DSA-512")
	sig, _ := kp.SignDeterministic(msg, []byte("bench-verify-seed"), DomainNone())
	pk := kp.PublicKey()
	sigBytes := sig.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(sigBytes, pk, msg, DomainNone()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify512_SHA256(b *testing.B) {
	kp, _ := GenerateDeterministic([]byte("bench-key-512"), 9)
	msg := []byte("Benchmark message for FN-DSA-512")
	domain, _ := DomainPrehashed(PreHashSHA256, nil)
	sig, _ := kp.SignDeterministic(msg, []byte("bench-verify-seed-ph"), domain)
	pk := kp.PublicKey()
	sigBytes := sig.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(sigBytes, pk, msg, domain); err != nil {
			b.Fatal(err)
		}
	}
}

// ── FN-DSA-1024 Benchmarks ──────────────────────────────────────────────────

func BenchmarkKeygen1024(b *testing.B) {
	seed := []byte("bench-keygen-seed-1024")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := GenerateDeterministic(seed, 10); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign1024_None(b *testing.B) {
	kp, _ := GenerateDeterministic([]byte("bench-key-1024"), 10)
	msg := []byte("Benchmark message for FN-DSA-1024")
	seed := []byte("bench-sign-seed-1024")
	domain := DomainNone()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := kp.SignDeterministic(msg, seed, domain); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify1024_None(b *testing.B) {
	kp, _ := GenerateDeterministic([]byte("bench-key-1024"), 10)
	msg := []byte("Benchmark message for FN-DSA-1024")
	sig, _ := kp.SignDeterministic(msg, []byte("bench-verify-seed-1024"), DomainNone())
	pk := kp.PublicKey()
	sigBytes := sig.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(sigBytes, pk, msg, DomainNone()); err != nil {
			b.Fatal(err)
		}
	}
}

// ── Expanded Key Benchmarks ─────────────────────────────────────────────────

func BenchmarkExpand512(b *testing.B) {
	kp, _ := GenerateDeterministic([]byte("bench-expand-key"), 9)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := kp.Expand(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignExpanded512_None(b *testing.B) {
	kp, _ := GenerateDeterministic([]byte("bench-expand-key"), 9)
	ek, _ := kp.Expand()
	msg := []byte("Benchmark message for expanded key")
	seed := []byte("bench-sign-seed")
	domain := DomainNone()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ek.SignDeterministic(msg, seed, domain); err != nil {
			b.Fatal(err)
		}
	}
}
