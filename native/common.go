package native

var l2Bound = [11]uint32{
	0,
	101498, 208714, 428865, 892039, 1852696,
	3842630, 7959734, 16468416, 34034726, 70265242,
}

var hashToPointOvertab = [11]uint16{
	0,
	65, 67, 71, 77, 86, 100, 122, 154, 205, 287,
}

// HashToPointVarTime maps a flipped SHAKE256 context to a polynomial modulo q.
func HashToPointVarTime(sc *Shake256Context, x []uint16, logn uint) {
	n := 1 << int(logn)
	pos := 0
	var buf [2]byte
	for pos < n {
		Shake256Extract(sc, buf[:])
		w := (uint32(buf[0]) << 8) | uint32(buf[1])
		if w < 61445 {
			for w >= 12289 {
				w -= 12289
			}
			x[pos] = uint16(w)
			pos++
		}
	}
}

// HashToPointCT maps a flipped SHAKE256 context to a polynomial modulo q with
// Falcon's oversampling and squeeze procedure.
func HashToPointCT(sc *Shake256Context, x []uint16, logn uint, _ []byte) {
	n := 1 << int(logn)
	over := int(hashToPointOvertab[logn])
	m := n + over
	values := make([]uint16, m)
	var buf [2]byte

	for i := 0; i < m; i++ {
		Shake256Extract(sc, buf[:])
		w := (uint32(buf[0]) << 8) | uint32(buf[1])
		wr := reduceHashPointWord(w)
		values[i] = uint16(wr)
	}

	for p := 1; p <= over; p <<= 1 {
		v := 0
		for u := 0; u < m; u++ {
			sv := values[u]
			j := u - v
			mk := uint16(sv>>15) - 1
			v += int(mk) & 1
			if u < p {
				continue
			}

			dv := values[u-p]
			mk2 := mk & uint16(-int16(((uint32(j&p)+0x1ff)>>9)&1))
			newS := sv ^ (mk2 & (sv ^ dv))
			newD := dv ^ (mk2 & (sv ^ dv))
			values[u] = newS
			values[u-p] = newD
		}
	}
	copy(x[:n], values[:n])
}

func reduceHashPointWord(w uint32) uint32 {
	wr := w
	wr -= 24578 & (((wr - 24578) >> 31) - 1)
	wr -= 24578 & (((wr - 24578) >> 31) - 1)
	wr -= 12289 & (((wr - 12289) >> 31) - 1)
	wr |= ((w - 61445) >> 31) - 1
	return wr
}

// IsShort reports whether signature vectors are within Falcon's squared L2 bound.
func IsShort(s1, s2 []int16, logn uint) bool {
	n := 1 << int(logn)
	var s uint32
	var ng uint32
	for i := 0; i < n; i++ {
		z := int32(s1[i])
		s += uint32(z * z)
		ng |= s
		z = int32(s2[i])
		s += uint32(z * z)
		ng |= s
	}
	s |= uint32(-int32(ng >> 31))
	return s <= l2Bound[logn]
}

// IsShortHalf reports whether s2 is short enough given a saturated s1 norm.
func IsShortHalf(sqn uint32, s2 []int16, logn uint) bool {
	n := 1 << int(logn)
	ng := uint32(-int32(sqn >> 31))
	for i := 0; i < n; i++ {
		z := int32(s2[i])
		sqn += uint32(z * z)
		ng |= sqn
	}
	sqn |= uint32(-int32(ng >> 31))
	return sqn <= l2Bound[logn]
}
