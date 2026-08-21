package apb

import (
	"fmt"

	"apb-sniffer/ue3"
)

type FieldObservation struct {
	Index uint32

	Name  string
	Known bool

	BeginBit int
	EndBit   int

	IndexBits int

	RawBits []byte
}

func DecodeControllerFields(
	bunch ue3.Bunch,
	fieldMax uint32,
) ([]FieldObservation, error) {
	if bunch.Kind != ue3.BunchData {
		return nil, fmt.Errorf("not a data bunch")
	}

	if bunch.DataBitCount == 0 {
		return nil, fmt.Errorf("empty bunch")
	}

	reader := ue3.NewBitReader(
		bunch.RawData,
		0,
		int(bunch.DataBitCount),
	)

	var result []FieldObservation

	for reader.Remaining() > 0 {
		begin := reader.Tell()

		fieldIndex, err := reader.ReadBoundedInt(fieldMax)
		if err != nil {
			return result, fmt.Errorf(
				"field index at bit %d: %w",
				begin,
				err,
			)
		}

		indexBits := reader.Tell() - begin

		field := FieldObservation{
			Index:     fieldIndex,
			BeginBit:  begin,
			IndexBits: indexBits,
		}

		if definition, ok := LookupField(fieldIndex); ok {
			field.Known = true
			field.Name = definition.Name

			if definition.TotalBits > 0 {
				parameterBits :=
					definition.TotalBits - indexBits

				if parameterBits < 0 {
					return result, fmt.Errorf(
						"field %d: index bits %d > total bits %d",
						fieldIndex,
						indexBits,
						definition.TotalBits,
					)
				}

				if parameterBits > reader.Remaining() {
					return result, fmt.Errorf(
						"field %d truncated: need=%d remaining=%d",
						fieldIndex,
						parameterBits,
						reader.Remaining(),
					)
				}

				raw, err := reader.ReadBits(parameterBits)
				if err != nil {
					return result, err
				}

				_ = raw

				field.EndBit = reader.Tell()

				result = append(result, field)

				continue
			}
		}

		// We don't know the parameter width.
		//
		// IMPORTANT:
		// Do not guess it here. APBEMU also stops at an unknown
		// controller field because consuming the wrong number of
		// bits would corrupt all following fields.
		field.EndBit = reader.Tell()

		result = append(result, field)

		return result, fmt.Errorf(
			"unknown field %d at bit %d; parameter width unknown",
			fieldIndex,
			begin,
		)
	}

	return result, nil
}
