package native

var MaxFGBits = [11]uint8{0, 8, 8, 8, 8, 8, 7, 7, 6, 6, 5}
var MaxFGBitsUpper = [11]uint8{0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8}
var MaxSigBits = [11]uint8{0, 10, 11, 11, 12, 12, 12, 12, 12, 12, 12}

// ModqEncode encodes mod-q coefficients with packed 14-bit words.
// If out is nil, it returns the required encoded length.
func ModqEncode(out []byte, x []uint16, logn uint) int {
	n := 1 << int(logn)
	for i := 0; i < n; i++ {
		if x[i] >= 12289 {
			return 0
		}
	}
	outLen := (n*14 + 7) >> 3
	if out == nil {
		return outLen
	}
	if outLen > len(out) {
		return 0
	}

	var acc uint32
	accLen := 0
	pos := 0
	for i := 0; i < n; i++ {
		acc = (acc << 14) | uint32(x[i])
		accLen += 14
		for accLen >= 8 {
			accLen -= 8
			out[pos] = byte(acc >> accLen)
			pos++
		}
	}
	if accLen > 0 {
		out[pos] = byte(acc << (8 - accLen))
	}
	return outLen
}

// ModqDecode decodes packed 14-bit mod-q coefficients.
func ModqDecode(x []uint16, logn uint, input []byte) int {
	n := 1 << int(logn)
	inLen := (n*14 + 7) >> 3
	if inLen > len(input) {
		return 0
	}

	var acc uint32
	accLen := 0
	u := 0
	pos := 0
	for u < n {
		acc = (acc << 8) | uint32(input[pos])
		pos++
		accLen += 8
		if accLen >= 14 {
			accLen -= 14
			w := (acc >> accLen) & 0x3fff
			if w >= 12289 {
				return 0
			}
			x[u] = uint16(w)
			u++
		}
	}
	if accLen > 0 && (acc&((uint32(1)<<accLen)-1)) != 0 {
		return 0
	}
	return inLen
}

// TrimI16Encode encodes signed coefficients with a fixed bit width.
// If out is nil, it returns the required encoded length.
func TrimI16Encode(out []byte, x []int16, logn uint, bits uint) int {
	n := 1 << int(logn)
	maxv := (int32(1) << (bits - 1)) - 1
	minv := -maxv
	for i := 0; i < n; i++ {
		v := int32(x[i])
		if v < minv || v > maxv {
			return 0
		}
	}
	outLen := (n*int(bits) + 7) >> 3
	if out == nil {
		return outLen
	}
	if outLen > len(out) {
		return 0
	}

	var acc uint32
	var accLen uint
	mask := (uint32(1) << bits) - 1
	pos := 0
	for i := 0; i < n; i++ {
		acc = (acc << bits) | (uint32(uint16(x[i])) & mask)
		accLen += bits
		for accLen >= 8 {
			accLen -= 8
			out[pos] = byte(acc >> accLen)
			pos++
		}
	}
	if accLen > 0 {
		out[pos] = byte(acc << (8 - accLen))
	}
	return outLen
}

// TrimI16Decode decodes signed coefficients with a fixed bit width.
func TrimI16Decode(x []int16, logn uint, bits uint, input []byte) int {
	n := 1 << int(logn)
	inLen := (n*int(bits) + 7) >> 3
	if inLen > len(input) {
		return 0
	}

	u := 0
	var acc uint32
	var accLen uint
	mask1 := (uint32(1) << bits) - 1
	mask2 := uint32(1) << (bits - 1)
	pos := 0
	for u < n {
		acc = (acc << 8) | uint32(input[pos])
		pos++
		accLen += 8
		for accLen >= bits && u < n {
			accLen -= bits
			w := (acc >> accLen) & mask1
			w |= uint32(-int32(w & mask2))
			if w == uint32(-int32(mask2)) {
				return 0
			}
			w |= uint32(-int32(w & mask2))
			x[u] = int16(int32(w))
			u++
		}
	}
	if accLen > 0 && (acc&((uint32(1)<<accLen)-1)) != 0 {
		return 0
	}
	return inLen
}

// TrimI8Encode encodes signed 8-bit coefficients with a fixed bit width.
// If out is nil, it returns the required encoded length.
func TrimI8Encode(out []byte, x []int8, logn uint, bits uint) int {
	n := 1 << int(logn)
	maxv := (int32(1) << (bits - 1)) - 1
	minv := -maxv
	for i := 0; i < n; i++ {
		v := int32(x[i])
		if v < minv || v > maxv {
			return 0
		}
	}
	outLen := (n*int(bits) + 7) >> 3
	if out == nil {
		return outLen
	}
	if outLen > len(out) {
		return 0
	}

	var acc uint32
	var accLen uint
	mask := (uint32(1) << bits) - 1
	pos := 0
	for i := 0; i < n; i++ {
		acc = (acc << bits) | (uint32(uint8(x[i])) & mask)
		accLen += bits
		for accLen >= 8 {
			accLen -= 8
			out[pos] = byte(acc >> accLen)
			pos++
		}
	}
	if accLen > 0 {
		out[pos] = byte(acc << (8 - accLen))
	}
	return outLen
}

// TrimI8Decode decodes signed 8-bit coefficients with a fixed bit width.
func TrimI8Decode(x []int8, logn uint, bits uint, input []byte) int {
	n := 1 << int(logn)
	inLen := (n*int(bits) + 7) >> 3
	if inLen > len(input) {
		return 0
	}

	u := 0
	var acc uint32
	var accLen uint
	mask1 := (uint32(1) << bits) - 1
	mask2 := uint32(1) << (bits - 1)
	pos := 0
	for u < n {
		acc = (acc << 8) | uint32(input[pos])
		pos++
		accLen += 8
		for accLen >= bits && u < n {
			accLen -= bits
			w := (acc >> accLen) & mask1
			w |= uint32(-int32(w & mask2))
			if w == uint32(-int32(mask2)) {
				return 0
			}
			x[u] = int8(int32(w))
			u++
		}
	}
	if accLen > 0 && (acc&((uint32(1)<<accLen)-1)) != 0 {
		return 0
	}
	return inLen
}

// CompEncode encodes signature coefficients with Falcon compressed format.
// If out is nil, it returns the required encoded length.
func CompEncode(out []byte, x []int16, logn uint) int {
	n := 1 << int(logn)
	for i := 0; i < n; i++ {
		if x[i] < -2047 || x[i] > 2047 {
			return 0
		}
	}

	var acc uint32
	var accLen uint
	pos := 0
	for i := 0; i < n; i++ {
		acc <<= 1
		t := int32(x[i])
		if t < 0 {
			t = -t
			acc |= 1
		}
		w := uint32(t)

		acc <<= 7
		acc |= w & 127
		w >>= 7
		accLen += 8

		acc <<= w + 1
		acc |= 1
		accLen += uint(w + 1)

		for accLen >= 8 {
			accLen -= 8
			if out != nil {
				if pos >= len(out) {
					return 0
				}
				out[pos] = byte(acc >> accLen)
			}
			pos++
		}
	}

	if accLen > 0 {
		if out != nil {
			if pos >= len(out) {
				return 0
			}
			out[pos] = byte(acc << (8 - accLen))
		}
		pos++
	}

	return pos
}

// CompDecode decodes Falcon compressed signature coefficients.
func CompDecode(x []int16, logn uint, input []byte) int {
	n := 1 << int(logn)
	maxInLen := len(input)
	var acc uint32
	var accLen uint
	pos := 0

	for i := 0; i < n; i++ {
		if pos >= maxInLen {
			return 0
		}
		acc = (acc << 8) | uint32(input[pos])
		pos++
		b := acc >> accLen
		s := b & 128
		m := b & 127

		for {
			if accLen == 0 {
				if pos >= maxInLen {
					return 0
				}
				acc = (acc << 8) | uint32(input[pos])
				pos++
				accLen = 8
			}
			accLen--
			if ((acc >> accLen) & 1) != 0 {
				break
			}
			m += 128
			if m > 2047 {
				return 0
			}
		}

		if s != 0 && m == 0 {
			return 0
		}
		if s != 0 {
			x[i] = int16(-int32(m))
		} else {
			x[i] = int16(m)
		}
	}

	if accLen > 0 && (acc&((uint32(1)<<accLen)-1)) != 0 {
		return 0
	}
	return pos
}
