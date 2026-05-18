package native

import (
	"crypto"

	"github.com/lattice-safe/falcon-go/internal/fndsa"
)

const rawFalconHash = crypto.Hash(0xffffffff)

// FalconGetLogN extracts logn from an encoded key or signature object.
func FalconGetLogN(obj []byte) int {
	if len(obj) == 0 {
		return ErrFormat
	}
	logn := int(obj[0] & 0x0f)
	if logn < 1 || logn > 10 {
		return ErrFormat
	}
	return logn
}

// FalconKeygenMake generates an encoded private key and, optionally, public key.
func FalconKeygenMake(rng *Shake256Context, logn uint, privkey []byte, pubkey []byte, _ []byte) int {
	if rng == nil || logn < 2 || logn > 10 {
		return ErrBadArg
	}
	if len(privkey) < PrivKeySize(logn) || (pubkey != nil && len(pubkey) < PubKeySize(logn)) {
		return ErrSize
	}
	seed := rngSeedMaterial(rng)
	sk, pk, err := fndsa.KeyGenDeterministic(logn, seed)
	if err != nil {
		return ErrInternal
	}
	copy(privkey, sk)
	if pubkey != nil {
		copy(pubkey, pk)
	}
	return 0
}

// FalconMakePublic recomputes an encoded public key from an encoded private key.
func FalconMakePublic(pubkey []byte, privkey []byte, _ []byte) int {
	logn := privateLogN(privkey)
	if logn < 0 {
		return ErrFormat
	}
	if len(pubkey) < PubKeySize(uint(logn)) {
		return ErrSize
	}
	pk, err := fndsa.MakePublic(privkey)
	if err != nil {
		return ErrFormat
	}
	copy(pubkey, pk)
	return 0
}

// FalconSignStart extracts a nonce from rng and initializes hashData with it.
func FalconSignStart(rng *Shake256Context, nonce []byte, hashData *Shake256Context) int {
	if rng == nil || hashData == nil || len(nonce) < 40 {
		return ErrBadArg
	}
	Shake256Extract(rng, nonce[:40])
	Shake256Init(hashData)
	Shake256Inject(hashData, nonce[:40])
	return 0
}

// FalconSignDynFinish finishes a streamed signature.
func FalconSignDynFinish(rng *Shake256Context, sig []byte, sigLen *int, sigType int, privkey []byte, hashData *Shake256Context, nonce []byte, _ []byte) int {
	if rng == nil || sigLen == nil || hashData == nil || len(nonce) < 40 {
		return ErrBadArg
	}
	logn := privateLogN(privkey)
	if logn < 0 {
		return ErrFormat
	}
	size := signatureBufferSize(uint(logn), sigType)
	if size == 0 {
		return ErrBadArg
	}
	if len(sig) < size || *sigLen < size {
		return ErrSize
	}
	data, ok := hashDataPayload(hashData, nonce[:40])
	if !ok {
		return ErrFormat
	}
	prepared, err := fndsa.PrepareSigningKey(privkey)
	if err != nil {
		return ErrFormat
	}
	stream := make([]byte, 56*32)
	Shake256Extract(rng, stream)
	var out []byte
	switch sigType {
	case SigCT:
		out, err = prepared.SignCTWithNonceSampler(nonce[:40], stream, nil, rawFalconHash, data)
	case SigPadded:
		out, err = prepared.SignPaddedWithNonceSampler(nonce[:40], stream, nil, rawFalconHash, data)
	case SigCompressed:
		out, err = prepared.SignPaddedWithNonceSampler(nonce[:40], stream, nil, rawFalconHash, data)
		if err == nil {
			out = trimCompressedPadding(out)
		}
	default:
		return ErrBadArg
	}
	if err != nil {
		return ErrInternal
	}
	copy(sig, out)
	*sigLen = len(out)
	return 0
}

// FalconSignDyn signs data in one call with the dynamic private-key path.
func FalconSignDyn(rng *Shake256Context, sig []byte, sigLen *int, sigType int, privkey []byte, data []byte, tmp []byte) int {
	var nonce [40]byte
	var hd Shake256Context
	if rc := FalconSignStart(rng, nonce[:], &hd); rc != 0 {
		return rc
	}
	Shake256Inject(&hd, data)
	return FalconSignDynFinish(rng, sig, sigLen, sigType, privkey, &hd, nonce[:], tmp)
}

// FalconVerifyStart initializes hashData with the nonce embedded in sig.
func FalconVerifyStart(hashData *Shake256Context, sig []byte) int {
	if hashData == nil || len(sig) < 41 {
		return ErrFormat
	}
	Shake256Init(hashData)
	Shake256Inject(hashData, sig[1:41])
	return 0
}

// FalconVerifyFinish finishes streamed verification.
func FalconVerifyFinish(sig []byte, sigType int, pubkey []byte, hashData *Shake256Context, _ []byte) int {
	if hashData == nil || len(sig) < 41 {
		return ErrFormat
	}
	logn := publicLogN(pubkey)
	if logn < 0 {
		return ErrFormat
	}
	if int(sig[0]&0x0f) != logn {
		return ErrBadSig
	}
	data, ok := hashDataPayload(hashData, sig[1:41])
	if !ok {
		return ErrFormat
	}
	switch sigType {
	case 0:
		switch sig[0] & 0xf0 {
		case 0x50:
			if !fndsa.VerifyCT(pubkey, nil, rawFalconHash, data, sig) {
				return ErrBadSig
			}
			return 0
		case 0x30:
			return verifyPadded(pubkey, data, sig)
		default:
			return ErrBadSig
		}
	case SigCT:
		if (sig[0] & 0xf0) != 0x50 {
			return ErrFormat
		}
		if !fndsa.VerifyCT(pubkey, nil, rawFalconHash, data, sig) {
			return ErrBadSig
		}
		return 0
	case SigPadded, SigCompressed:
		if (sig[0] & 0xf0) != 0x30 {
			return ErrFormat
		}
		if sigType == SigCompressed {
			sig = padCompressedForVerify(sig, uint(logn))
			if sig == nil {
				return ErrFormat
			}
		}
		return verifyPadded(pubkey, data, sig)
	default:
		return ErrBadArg
	}
}

// FalconVerify verifies data in one call.
func FalconVerify(sig []byte, sigType int, pubkey []byte, data []byte, tmp []byte) int {
	var hd Shake256Context
	if rc := FalconVerifyStart(&hd, sig); rc != 0 {
		return rc
	}
	Shake256Inject(&hd, data)
	return FalconVerifyFinish(sig, sigType, pubkey, &hd, tmp)
}

func signatureBufferSize(logn uint, sigType int) int {
	switch sigType {
	case SigCT:
		return SigCTSize(logn)
	case SigPadded:
		return SigPaddedSize(logn)
	case SigCompressed:
		return SigCompressedMaxSize(logn)
	default:
		return 0
	}
}

func trimCompressedPadding(sig []byte) []byte {
	n := len(sig)
	for n > 41 && sig[n-1] == 0 {
		n--
	}
	out := make([]byte, n)
	copy(out, sig[:n])
	return out
}

func padCompressedForVerify(sig []byte, logn uint) []byte {
	size := SigPaddedSize(logn)
	if len(sig) > size {
		return nil
	}
	out := make([]byte, size)
	copy(out, sig)
	return out
}

func verifyPadded(pubkey []byte, data []byte, sig []byte) int {
	logn := publicLogN(pubkey)
	if logn < 0 {
		return ErrFormat
	}
	ok := false
	if logn >= 9 {
		ok = fndsa.Verify(pubkey, nil, rawFalconHash, data, sig)
	} else {
		ok = fndsa.VerifyWeak(pubkey, nil, rawFalconHash, data, sig)
	}
	if !ok {
		return ErrBadSig
	}
	return 0
}

func privateLogN(privkey []byte) int {
	if len(privkey) == 0 || (privkey[0]&0xf0) != 0x50 {
		return -1
	}
	logn := int(privkey[0] & 0x0f)
	if logn < 2 || logn > 10 || len(privkey) != PrivKeySize(uint(logn)) {
		return -1
	}
	return logn
}

func publicLogN(pubkey []byte) int {
	if len(pubkey) == 0 || (pubkey[0]&0xf0) != 0x00 {
		return -1
	}
	logn := int(pubkey[0] & 0x0f)
	if logn < 2 || logn > 10 || len(pubkey) != PubKeySize(uint(logn)) {
		return -1
	}
	return logn
}

func rngSeedMaterial(rng *Shake256Context) []byte {
	if len(rng.transcript) != 0 && rng.extracted == 0 {
		seed := make([]byte, len(rng.transcript))
		copy(seed, rng.transcript)
		return seed
	}
	seed := make([]byte, 48)
	Shake256Extract(rng, seed)
	return seed
}

func hashDataPayload(hashData *Shake256Context, nonce []byte) ([]byte, bool) {
	if len(hashData.transcript) < len(nonce) {
		return nil, false
	}
	if string(hashData.transcript[:len(nonce)]) != string(nonce) {
		return nil, false
	}
	data := make([]byte, len(hashData.transcript)-len(nonce))
	copy(data, hashData.transcript[len(nonce):])
	return data, true
}
