package ue3

import "fmt"

type BunchKind uint8

const (
	BunchData BunchKind = iota
	BunchAck
)

type Bunch struct {
	Kind BunchKind

	Open     bool
	Close    bool
	Reliable bool

	ChannelIndex    uint16
	ChannelSequence uint16
	ChannelType     uint8

	DataBitCount  uint16
	DataBitOffset int

	RawData []byte

	AckPacketID uint32
}

type Packet struct {
	Valid bool
	Error string

	Prefix          uint16
	PacketID        uint32
	PayloadBitCount int

	Bunches []Bunch
}

func findPayloadBitCount(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("empty packet")
	}

	// UE3 uses the highest set bit in the final non-zero byte
	// as the packet trailer marker.
	for i := len(data) - 1; i >= 0; i-- {
		value := data[i]

		if value == 0 {
			continue
		}

		for bit := 7; bit >= 0; bit-- {
			if value&(1<<bit) != 0 {
				return i*8 + bit, nil
			}
		}
	}

	return 0, fmt.Errorf("missing UE3 trailer marker")
}

func extractBits(
	data []byte,
	beginBit int,
	bitCount int,
) []byte {
	result := make([]byte, (bitCount+7)/8)

	for i := 0; i < bitCount; i++ {
		sourceBit := beginBit + i

		value := (data[sourceBit/8] >> (sourceBit % 8)) & 1

		if value != 0 {
			result[i/8] |= 1 << (i % 8)
		}
	}

	return result
}

func ParsePacket(data []byte) (Packet, error) {
	var packet Packet

	payloadBitCount, err := findPayloadBitCount(data)
	if err != nil {
		packet.Error = err.Error()
		return packet, err
	}

	packet.PayloadBitCount = payloadBitCount

	reader := NewBitReader(
		data,
		0,
		payloadBitCount,
	)

	var value uint32

	// ------------------------------------------------------------
	// Packet ID
	// ------------------------------------------------------------

	if value, err = reader.ReadBits(16); err != nil {
		packet.Error = "truncated packet id (low)"
		return packet, err
	}

	packet.Prefix = uint16(value)

	packetIDLow := value

	if value, err = reader.ReadBits(14); err != nil {
		packet.Error = "truncated packet id (high)"
		return packet, err
	}

	// APBEMU:
	//
	// packet.PacketId = static_cast<uint16_t>(packetIdLow);
	//
	// The next 14 bits are NOT part of the client packet ID.
	packet.PacketID = packetIDLow

	// ------------------------------------------------------------
	// Bunches
	// ------------------------------------------------------------

	for reader.Remaining() > 0 {
		var bunch Bunch

		flag, err := reader.ReadBit()
		if err != nil {
			packet.Error = "truncated ACK/data flag"
			return packet, err
		}

		if flag {
			// ----------------------------------------------------
			// ACK
			// ----------------------------------------------------

			bunch.Kind = BunchAck

			hasAckID, err := reader.ReadBit()
			if err != nil {
				packet.Error = "truncated ACK id presence flag"
				return packet, err
			}

			if hasAckID {
				ackID, err := reader.ReadBits(30)
				if err != nil {
					packet.Error = "truncated ACK packet id"
					return packet, err
				}

				bunch.AckPacketID = ackID
			}

			packet.Bunches = append(
				packet.Bunches,
				bunch,
			)

			continue
		}

		// --------------------------------------------------------
		// DATA
		// --------------------------------------------------------

		bunch.Kind = BunchData

		hasOpenClose, err := reader.ReadBit()
		if err != nil {
			packet.Error = "truncated open/close presence flag"
			return packet, err
		}

		if hasOpenClose {
			if bunch.Open, err = reader.ReadBit(); err != nil {
				packet.Error = "truncated open flag"
				return packet, err
			}

			if bunch.Close, err = reader.ReadBit(); err != nil {
				packet.Error = "truncated close flag"
				return packet, err
			}
		}

		if bunch.Reliable, err = reader.ReadBit(); err != nil {
			packet.Error = "truncated reliability flag"
			return packet, err
		}

		// Channel index

		value, err = reader.ReadBits(10)
		if err != nil {
			packet.Error = "truncated channel index"
			return packet, err
		}

		bunch.ChannelIndex = uint16(value)

		// Reliable sequence

		if bunch.Reliable {
			value, err = reader.ReadBits(10)
			if err != nil {
				packet.Error = "truncated channel sequence"
				return packet, err
			}

			bunch.ChannelSequence = uint16(value)
		}

		// Channel type

		if bunch.Reliable || bunch.Open {
			value, err = reader.ReadBits(3)
			if err != nil {
				packet.Error = "truncated channel type"
				return packet, err
			}

			bunch.ChannelType = uint8(value)
		}

		// Data length

		value, err = reader.ReadBits(12)
		if err != nil {
			packet.Error = "truncated bunch data length"
			return packet, err
		}

		bunch.DataBitCount = uint16(value)
		bunch.DataBitOffset = reader.Tell()

		if int(bunch.DataBitCount) > reader.Remaining() {
			packet.Error = fmt.Sprintf(
				"bunch data exceeds packet payload: data=%d remaining=%d",
				bunch.DataBitCount,
				reader.Remaining(),
			)

			return packet, fmt.Errorf("%s", packet.Error)
		}

		// Extract raw bunch payload.

		bunch.RawData = extractBits(
			reader.Data(),
			bunch.DataBitOffset,
			int(bunch.DataBitCount),
		)

		// Advance over bunch data.

		if err := reader.Skip(int(bunch.DataBitCount)); err != nil {
			packet.Error = "failed to advance over bunch data"
			return packet, err
		}

		packet.Bunches = append(
			packet.Bunches,
			bunch,
		)
	}

	packet.Valid = true

	return packet, nil
}

func parseBunch(reader *BitReader) (Bunch, error) {
	var bunch Bunch

	flag, err := reader.ReadBit()
	if err != nil {
		return bunch, fmt.Errorf(
			"truncated ACK/data flag: %w",
			err,
		)
	}

	if flag {
		return parseAckBunch(reader)
	}

	return parseDataBunch(reader)
}

func parseAckBunch(reader *BitReader) (Bunch, error) {
	bunch := Bunch{
		Kind: BunchAck,
	}

	hasID, err := reader.ReadBit()
	if err != nil {
		return bunch, fmt.Errorf(
			"truncated ACK presence flag: %w",
			err,
		)
	}

	if hasID {
		id, err := reader.ReadBits(30)
		if err != nil {
			return bunch, fmt.Errorf(
				"truncated ACK packet id: %w",
				err,
			)
		}

		bunch.AckPacketID = id
	}

	return bunch, nil
}

func readerData(r *BitReader) []byte {
	return r.Data()
}

func parseDataBunch(reader *BitReader) (Bunch, error) {
	bunch := Bunch{
		Kind: BunchData,
	}

	start := reader.Tell()

	hasOpenClose, err := reader.ReadBit()
	if err != nil {
		return bunch, fmt.Errorf(
			"truncated open/close flag: %w",
			err,
		)
	}

	fmt.Printf(
		"    DATA start=%d openClose=%v\n",
		start,
		hasOpenClose,
	)

	if hasOpenClose {
		bunch.Open, err = reader.ReadBit()
		if err != nil {
			return bunch, fmt.Errorf(
				"truncated open flag: %w",
				err,
			)
		}

		bunch.Close, err = reader.ReadBit()
		if err != nil {
			return bunch, fmt.Errorf(
				"truncated close flag: %w",
				err,
			)
		}
	}

	bunch.Reliable, err = reader.ReadBit()
	if err != nil {
		return bunch, fmt.Errorf(
			"truncated reliable flag: %w",
			err,
		)
	}

	fmt.Printf(
		"    open=%v close=%v reliable=%v pos=%d\n",
		bunch.Open,
		bunch.Close,
		bunch.Reliable,
		reader.Tell(),
	)

	channel, err := reader.ReadBits(10)
	if err != nil {
		return bunch, fmt.Errorf(
			"truncated channel index: %w",
			err,
		)
	}

	bunch.ChannelIndex = uint16(channel)

	fmt.Printf(
		"    channel=%d pos=%d\n",
		bunch.ChannelIndex,
		reader.Tell(),
	)

	if bunch.Reliable {
		sequence, err := reader.ReadBits(10)
		if err != nil {
			return bunch, fmt.Errorf(
				"truncated channel sequence: %w",
				err,
			)
		}

		bunch.ChannelSequence = uint16(sequence)

		fmt.Printf(
			"    sequence=%d pos=%d\n",
			bunch.ChannelSequence,
			reader.Tell(),
		)
	}

	if bunch.Reliable || bunch.Open {
		channelType, err := reader.ReadBits(3)
		if err != nil {
			return bunch, fmt.Errorf(
				"truncated channel type: %w",
				err,
			)
		}

		bunch.ChannelType = uint8(channelType)

		fmt.Printf(
			"    channelType=%d pos=%d\n",
			bunch.ChannelType,
			reader.Tell(),
		)
	}

	dataBits, err := reader.ReadBits(12)
	if err != nil {
		return bunch, fmt.Errorf(
			"truncated bunch data length: %w",
			err,
		)
	}

	bunch.DataBitCount = uint16(dataBits)

	fmt.Printf(
		"    dataBits=%d pos=%d remaining=%d\n",
		bunch.DataBitCount,
		reader.Tell(),
		reader.Remaining(),
	)
	bunch.DataBitOffset = reader.Tell()

	if int(bunch.DataBitCount) > reader.Remaining() {
		return bunch, fmt.Errorf(
			"bunch data exceeds packet payload: data=%d remaining=%d",
			bunch.DataBitCount,
			reader.Remaining(),
		)
	}

	bunch.RawData = extractBits(
		readerData(reader),
		bunch.DataBitOffset,
		int(bunch.DataBitCount),
	)

	if err := reader.Skip(int(bunch.DataBitCount)); err != nil {
		return bunch, fmt.Errorf(
			"failed to skip bunch data: %w",
			err,
		)
	}

	return bunch, nil
}
