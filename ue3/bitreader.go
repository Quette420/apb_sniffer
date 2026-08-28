package ue3

import "fmt"

type BitReader struct {
	data []byte
	pos  int
	end  int
}

func NewBitReader(data []byte, beginBit, endBit int) *BitReader {
	return &BitReader{
		data: data,
		pos:  beginBit,
		end:  endBit,
	}
}

func (r *BitReader) Tell() int {
	return r.pos
}

func (r *BitReader) Remaining() int {
	if r.pos > r.end {
		return 0
	}

	return r.end - r.pos
}

func (r *BitReader) ReadBit() (bool, error) {
	value, err := r.ReadBits(1)
	if err != nil {
		return false, err
	}

	return value != 0, nil
}

func (r *BitReader) ReadBits(count int) (uint32, error) {
	if count < 0 || count > 32 {
		return 0, fmt.Errorf("invalid bit count: %d", count)
	}

	if count > r.Remaining() {
		return 0, fmt.Errorf(
			"not enough bits: need=%d remaining=%d",
			count,
			r.Remaining(),
		)
	}

	var value uint32

	for i := 0; i < count; i++ {
		absolute := r.pos + i

		bit := (r.data[absolute/8] >> (absolute % 8)) & 1

		value |= uint32(bit) << i
	}

	r.pos += count

	return value, nil
}

func (r *BitReader) Skip(count int) error {
	if count < 0 || count > r.Remaining() {
		return fmt.Errorf("cannot skip %d bits", count)
	}

	r.pos += count

	return nil
}

func (r *BitReader) Data() []byte {
	return r.data
}

// ReadBoundedInt UE3 FBitReader::SerializeInt equivalent.
//
// Important: this is NOT ordinary fixed-width integer encoding.
// The number of bits depends on valueMax.
func (r *BitReader) ReadBoundedInt(valueMax uint32) (uint32, error) {
	if valueMax <= 1 {
		return 0, nil
	}

	var value uint32

	// UE3 FBitReader::ReadInt does not always consume ceil(log2(Max))
	// bits. The already accumulated value participates in the stop
	// condition. For example, field 345 with Max=634 consumes 9 bits.
	for mask := uint32(1); value+mask < valueMax; mask <<= 1 {
		bit, err := r.ReadBit()
		if err != nil {
			return 0, err
		}

		if bit {
			value |= mask
		}

		if mask == 0x80000000 {
			break
		}
	}

	return value, nil
}

func (r *BitReader) ReadBytes(count int) ([]byte, error) {
	result := make([]byte, count)

	for i := 0; i < count; i++ {
		value, err := r.ReadBits(8)
		if err != nil {
			return nil, err
		}

		result[i] = byte(value)
	}

	return result, nil
}
