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
