package ue3

import "testing"

func TestReadBoundedIntAPBControllerField(t *testing.T) {
	reader := NewBitReader(
		[]byte{0x59, 0x0B, 0, 0, 0, 0},
		0,
		42,
	)

	value, err := reader.ReadBoundedInt(634)
	if err != nil {
		t.Fatalf("ReadBoundedInt failed: %v", err)
	}

	if value != 345 {
		t.Fatalf("value = %d, want 345", value)
	}

	if reader.Tell() != 9 {
		t.Fatalf("position = %d, want 9", reader.Tell())
	}
}
