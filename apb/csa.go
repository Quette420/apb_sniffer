package apb

import (
	"fmt"
	"math"

	"apb-sniffer/ue3"
)

const PlayerControllerFieldMax uint32 = 634

var csaFieldNames = map[uint32]string{
	338: "ServerBeginCSA",
	339: "ServerTestCSA",
	340: "ServerCSAPredicted",
	341: "ClientMispredictedCSA",
	342: "ServerCSAPredictCancel",
	343: "ServerCSAKeyPressed",
	344: "ClientResetPendingCSA",
	345: "ServerCSAKeyReleased",
	426: "ClientCompleteAutoMoveToCSA",
	427: "ServerCompleteSuccessfulyAutoMoveToCSA",
}

type CSAObservation struct {
	FieldIndex    uint32
	FieldName     string
	IndexBits     int
	ParameterBits int
	ConsumedBits  int
	TrailingBits  int

	InputMappingPresent bool
	InputMapping        int32

	AimRotationPresent bool
	AimRotation        int32

	CameraPresent        bool
	CameraCollidePercent float32

	TargetPresent   bool
	TargetByChannel bool
	TargetReference uint32
}

// DecodeCSA decodes the first controller field when it belongs to the CSA
// family (338..345 plus the auto-move completion pair 426/427). The boolean
// result is false for an unrelated bunch.
func DecodeCSA(
	bunch ue3.Bunch,
	fieldMax uint32,
) (CSAObservation, bool, error) {
	var observation CSAObservation

	if bunch.Kind != ue3.BunchData || bunch.DataBitCount == 0 {
		return observation, false, nil
	}

	reader := ue3.NewBitReader(
		bunch.RawData,
		0,
		int(bunch.DataBitCount),
	)

	begin := reader.Tell()
	fieldIndex, err := reader.ReadBoundedInt(fieldMax)
	if err != nil {
		return observation, false, fmt.Errorf("CSA field index: %w", err)
	}

	fieldName, isCSA := csaFieldNames[fieldIndex]
	if !isCSA {
		return observation, false, nil
	}

	observation.FieldIndex = fieldIndex
	observation.FieldName = fieldName
	observation.IndexBits = reader.Tell() - begin
	observation.ParameterBits = reader.Remaining()

	readOptionalInt := func(
		present *bool,
		value *int32,
	) error {
		var err error
		*present, err = reader.ReadBit()
		if err != nil {
			return err
		}

		if !*present {
			return nil
		}

		raw, err := reader.ReadBits(32)
		if err != nil {
			return err
		}

		*value = int32(raw)
		return nil
	}

	switch fieldIndex {
	case 343:
		if err := readOptionalInt(
			&observation.InputMappingPresent,
			&observation.InputMapping,
		); err != nil {
			return observation, true, fmt.Errorf(
				"ServerCSAKeyPressed input mapping: %w",
				err,
			)
		}

		if err := readOptionalInt(
			&observation.AimRotationPresent,
			&observation.AimRotation,
		); err != nil {
			return observation, true, fmt.Errorf(
				"ServerCSAKeyPressed aim rotation: %w",
				err,
			)
		}

		observation.CameraPresent, err = reader.ReadBit()
		if err != nil {
			return observation, true, fmt.Errorf(
				"ServerCSAKeyPressed camera presence: %w",
				err,
			)
		}

		if observation.CameraPresent {
			raw, err := reader.ReadBits(32)
			if err != nil {
				return observation, true, fmt.Errorf(
					"ServerCSAKeyPressed camera value: %w",
					err,
				)
			}

			observation.CameraCollidePercent =
				math.Float32frombits(raw)
		}

		// RPC parameters carry a non-default/presence bit before the
		// property's own serialization. For an object that is followed by
		// the package-map selector and the channel/NetGUID reference.
		if reader.Remaining() > 0 {
			observation.TargetPresent, err = reader.ReadBit()
			if err != nil {
				return observation, true, fmt.Errorf(
					"ServerCSAKeyPressed target presence: %w",
					err,
				)
			}
		}

		if observation.TargetPresent {
			observation.TargetByChannel, err = reader.ReadBit()
			if err != nil {
				return observation, true, fmt.Errorf(
					"ServerCSAKeyPressed target kind: %w",
					err,
				)
			}

			targetMax := uint32(0x80000000)
			if observation.TargetByChannel {
				targetMax = 0x3FF
			}

			observation.TargetReference, err =
				reader.ReadBoundedInt(targetMax)
			if err != nil {
				return observation, true, fmt.Errorf(
					"ServerCSAKeyPressed target reference: %w",
					err,
				)
			}
		}

	case 345:
		if err := readOptionalInt(
			&observation.InputMappingPresent,
			&observation.InputMapping,
		); err != nil {
			return observation, true, fmt.Errorf(
				"ServerCSAKeyReleased input mapping: %w",
				err,
			)
		}
	}

	observation.ConsumedBits = reader.Tell()
	observation.TrailingBits = reader.Remaining()
	return observation, true, nil
}
