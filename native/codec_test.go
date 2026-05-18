package native

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestModqCodecRoundTrip(t *testing.T) {
	h := []uint16{7768, 1837, 4498, 1226, 9594, 8992, 2227, 6132, 2850, 7612, 4314, 3834, 2585, 3954, 6198, 589}
	encLen := ModqEncode(nil, h, 4)
	if encLen == 0 {
		t.Fatal("ModqEncode length returned zero")
	}
	encoded := make([]byte, encLen)
	if got := ModqEncode(encoded, h, 4); got != encLen {
		t.Fatalf("ModqEncode wrote %d, want %d", got, encLen)
	}
	decoded := make([]uint16, len(h))
	if got := ModqDecode(decoded, 4, encoded); got != encLen {
		t.Fatalf("ModqDecode consumed %d, want %d", got, encLen)
	}
	if !reflect.DeepEqual(decoded, h) {
		t.Fatalf("Modq round trip = %v, want %v", decoded, h)
	}
}

func TestTrimI8CodecRoundTrip(t *testing.T) {
	f := []int8{7, -7, 12, 18, 19, 6, 18, -18, 18, -17, -14, 51, 24, -17, 2, 31}
	bits := uint(MaxFGBits[4])
	encLen := TrimI8Encode(nil, f, 4, bits)
	if encLen == 0 {
		t.Fatal("TrimI8Encode length returned zero")
	}
	encoded := make([]byte, encLen)
	TrimI8Encode(encoded, f, 4, bits)
	decoded := make([]int8, len(f))
	if got := TrimI8Decode(decoded, 4, bits, encoded); got != encLen {
		t.Fatalf("TrimI8Decode consumed %d, want %d", got, encLen)
	}
	if !reflect.DeepEqual(decoded, f) {
		t.Fatalf("TrimI8 round trip = %v, want %v", decoded, f)
	}
}

func TestTrimI16CodecRoundTrip(t *testing.T) {
	coeffs := []int16{-10, -1, 0, 1, 33, 127, -127, 2047, -2047, 512, -512, 15, -15, 99, -100, 42}
	bits := uint(MaxSigBits[4])
	encLen := TrimI16Encode(nil, coeffs, 4, bits)
	if encLen == 0 {
		t.Fatal("TrimI16Encode length returned zero")
	}
	encoded := make([]byte, encLen)
	TrimI16Encode(encoded, coeffs, 4, bits)
	decoded := make([]int16, len(coeffs))
	if got := TrimI16Decode(decoded, 4, bits, encoded); got != encLen {
		t.Fatalf("TrimI16Decode consumed %d, want %d", got, encLen)
	}
	if !reflect.DeepEqual(decoded, coeffs) {
		t.Fatalf("TrimI16 round trip = %v, want %v", decoded, coeffs)
	}
}

func TestCompCodecRoundTrip(t *testing.T) {
	coeffs := []int16{-10, -1, 0, 1, 33, 127, -127, 2047, -2047, 512, -512, 15, -15, 99, -100, 42}
	encLen := CompEncode(nil, coeffs, 4)
	if encLen == 0 {
		t.Fatal("CompEncode length returned zero")
	}
	encoded := make([]byte, encLen)
	if got := CompEncode(encoded, coeffs, 4); got != encLen {
		t.Fatalf("CompEncode wrote %d, want %d", got, encLen)
	}
	decoded := make([]int16, len(coeffs))
	if got := CompDecode(decoded, 4, encoded); got != encLen {
		t.Fatalf("CompDecode consumed %d, want %d", got, encLen)
	}
	if !reflect.DeepEqual(decoded, coeffs) {
		t.Fatalf("Comp round trip = %v, want %v", decoded, coeffs)
	}
}

func TestPubKeyEncodingDegree16(t *testing.T) {
	expected, err := hex.DecodeString("04796072d46484ca95ea32022cd7f42c89dbc4368efa2864f7260d824d")
	if err != nil {
		t.Fatal(err)
	}
	h := []uint16{7768, 1837, 4498, 1226, 9594, 8992, 2227, 6132, 2850, 7612, 4314, 3834, 2585, 3954, 6198, 589}
	encoded := make([]byte, 256)
	encoded[0] = 4
	n := ModqEncode(encoded[1:], h, 4)
	if n == 0 {
		t.Fatal("ModqEncode returned zero")
	}
	if !bytes.Equal(encoded[:1+n], expected) {
		t.Fatalf("encoded public key = %x, want %x", encoded[:1+n], expected)
	}
}

func TestCodecErrors(t *testing.T) {
	// ModqEncode
	h := make([]uint16, 16)
	h[0] = 12290
	if ModqEncode(make([]byte, 28), h, 4) != 0 {
		t.Fatal("ModqEncode should reject large values")
	}
	h[0] = 10
	if ModqEncode(make([]byte, 2), h, 4) != 0 {
		t.Fatal("ModqEncode should reject small buffers")
	}

	// ModqDecode
	if ModqDecode(h, 4, make([]byte, 2)) != 0 {
		t.Fatal("ModqDecode should reject small buffers")
	}
	badModq := make([]byte, 28)
	badModq[0] = 0xff
	badModq[1] = 0xff // Will create w >= 12289
	if ModqDecode(h, 4, badModq) != 0 {
		t.Fatal("ModqDecode should reject invalid values")
	}
	// Non-zero padding
	validModq := make([]byte, 4) // logn=1, n=2, 2*14=28 bits -> 4 bytes. padding=4 bits
	ModqEncode(validModq, make([]uint16, 2), 1)
	validModq[3] |= 0x01
	if ModqDecode(make([]uint16, 2), 1, validModq) != 0 {
		t.Fatal("ModqDecode should reject non-zero padding")
	}

	// TrimI16Encode
	coeffs := make([]int16, 16)
	coeffs[0] = 4096 // Exceeds 12 bits max
	if TrimI16Encode(make([]byte, 24), coeffs, 4, 12) != 0 {
		t.Fatal("TrimI16Encode should reject out of bounds")
	}
	coeffs[0] = 10
	if TrimI16Encode(make([]byte, 2), coeffs, 4, 12) != 0 {
		t.Fatal("TrimI16Encode should reject short buffer")
	}

	// TrimI16Decode
	if TrimI16Decode(coeffs, 4, 12, make([]byte, 2)) != 0 {
		t.Fatal("TrimI16Decode should reject short buffer")
	}
	badTrim16 := make([]byte, 24)
	badTrim16[0] = 0x80
	badTrim16[1] = 0x00 // Might decode to -2048 which is mask2 (invalid)
	if TrimI16Decode(coeffs, 4, 12, badTrim16) != 0 {
		t.Fatal("TrimI16Decode should reject -2048")
	}
	validTrim16 := make([]byte, 3) // logn=1, n=2, bits=11 -> 22 bits -> 3 bytes
	TrimI16Encode(validTrim16, make([]int16, 2), 1, 11)
	validTrim16[2] |= 0x01
	if TrimI16Decode(make([]int16, 2), 1, 11, validTrim16) != 0 {
		t.Fatal("TrimI16Decode should reject non-zero padding")
	}

	// TrimI8Encode
	i8coeffs := make([]int8, 16)
	i8coeffs[0] = 127 // Exceeds 7 bits max
	if TrimI8Encode(make([]byte, 14), i8coeffs, 4, 7) != 0 {
		t.Fatal("TrimI8Encode should reject out of bounds")
	}
	i8coeffs[0] = 10
	if TrimI8Encode(make([]byte, 2), i8coeffs, 4, 7) != 0 {
		t.Fatal("TrimI8Encode should reject short buffer")
	}

	// TrimI8Decode
	if TrimI8Decode(i8coeffs, 4, 7, make([]byte, 2)) != 0 {
		t.Fatal("TrimI8Decode should reject short buffer")
	}
	badTrim8 := make([]byte, 14)
	badTrim8[0] = 0x80 // Decodes to -64 which is invalid for 7 bits
	if TrimI8Decode(i8coeffs, 4, 7, badTrim8) != 0 {
		t.Fatal("TrimI8Decode should reject -64")
	}
	validTrim8 := make([]byte, 2) // logn=1, n=2, bits=5 -> 10 bits -> 2 bytes
	TrimI8Encode(validTrim8, make([]int8, 2), 1, 5)
	validTrim8[1] |= 0x01
	if TrimI8Decode(make([]int8, 2), 1, 5, validTrim8) != 0 {
		t.Fatal("TrimI8Decode should reject non-zero padding")
	}

	// CompEncode
	coeffs[0] = 3000
	if CompEncode(make([]byte, 40), coeffs, 4) != 0 {
		t.Fatal("CompEncode should reject out of bounds")
	}
	coeffs[0] = 10
	if CompEncode(make([]byte, 1), coeffs, 4) != 0 {
		t.Fatal("CompEncode should reject short buffer inside loop")
	}
	if CompEncode(make([]byte, 16), make([]int16, 16), 4) != 0 { // Just enough to fail at end? No, 16*zeros needs 16 bits = 2 bytes. Let's make it 1 byte
		t.Fatal("CompEncode should reject short buffer at end")
	}

	// CompDecode
	if CompDecode(coeffs, 4, make([]byte, 1)) != 0 {
		t.Fatal("CompDecode should reject short buffer")
	}
	badComp := []byte{0xff, 0xff, 0xff, 0xff} // Lots of 1s -> m > 2047
	if CompDecode(coeffs, 4, badComp) != 0 {
		t.Fatal("CompDecode should reject m > 2047")
	}
	badComp2 := []byte{0x80, 0x00} // s=1, m=0
	if CompDecode(coeffs, 4, badComp2) != 0 {
		t.Fatal("CompDecode should reject s=1, m=0")
	}
	validComp := make([]byte, 2)
	CompEncode(validComp, make([]int16, 2), 1) // logn=1, n=2, 2 zeros = 2 bits -> 1 byte
	validComp[0] |= 0x20 // padding? 2 bits used, 6 bits padding
	if CompDecode(make([]int16, 2), 1, validComp) != 0 {
		t.Fatal("CompDecode should reject padding")
	}
}
