package apb

import (
	"testing"

	"apb-sniffer/ue3"
)

func TestDecodeCSAKeyReleasedFixture(t *testing.T) {
	bunch := ue3.Bunch{
		Kind:         ue3.BunchData,
		DataBitCount: 42,
		RawData: []byte{
			0x59, 0x0B, 0x00, 0x00, 0x00, 0x00,
		},
	}

	observation, isCSA, err := DecodeCSA(
		bunch,
		PlayerControllerFieldMax,
	)
	if err != nil {
		t.Fatalf("DecodeCSA failed: %v", err)
	}

	if !isCSA {
		t.Fatal("DecodeCSA did not recognize the CSA field")
	}

	if observation.FieldIndex != 345 {
		t.Fatalf(
			"FieldIndex = %d, want 345",
			observation.FieldIndex,
		)
	}

	if observation.IndexBits != 9 {
		t.Fatalf(
			"IndexBits = %d, want 9",
			observation.IndexBits,
		)
	}

	if !observation.InputMappingPresent ||
		observation.InputMapping != 2 {
		t.Fatalf(
			"InputMapping = %d present=%v, want 2 present",
			observation.InputMapping,
			observation.InputMappingPresent,
		)
	}

	if observation.ConsumedBits != 42 ||
		observation.TrailingBits != 0 {
		t.Fatalf(
			"consumed/trailing = %d/%d, want 42/0",
			observation.ConsumedBits,
			observation.TrailingBits,
		)
	}
}
