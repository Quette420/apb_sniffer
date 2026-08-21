package crypto

import "encoding/binary"

const bteaRounds = 6

var bteaDelta uint32 = 0x9E3779B9

func BTEADecrypt(data []byte, key [16]byte) bool {
	if len(data) < 8 || len(data)%4 != 0 {
		return false
	}

	n := len(data) / 4

	v := make([]uint32, n)

	for i := 0; i < n; i++ {
		v[i] = binary.LittleEndian.Uint32(
			data[i*4 : i*4+4],
		)
	}

	var k [4]uint32

	for i := 0; i < 4; i++ {
		k[i] = binary.LittleEndian.Uint32(
			key[i*4 : i*4+4],
		)
	}

	sum := uint32(bteaRounds) * bteaDelta

	y := v[0]

	for round := 0; round < bteaRounds; round++ {
		e := (sum >> 2) & 3

		for p := n - 1; p > 0; p-- {
			z := v[p-1]

			v[p] -= bteaMX(
				z,
				y,
				sum,
				k,
				e,
				uint32(p),
			)

			y = v[p]
		}

		z := v[n-1]

		v[0] -= bteaMX(
			z,
			y,
			sum,
			k,
			e,
			0,
		)

		y = v[0]
		sum -= bteaDelta
	}

	for i := 0; i < n; i++ {
		binary.LittleEndian.PutUint32(
			data[i*4:i*4+4],
			v[i],
		)
	}

	return true
}

func bteaMX(
	z uint32,
	y uint32,
	sum uint32,
	key [4]uint32,
	e uint32,
	p uint32,
) uint32 {
	return (((z >> 5) ^ (y << 2)) +
		((y >> 3) ^ (z << 4))) ^
		((sum ^ y) +
			(key[(p&3)^e] ^ z))
}
