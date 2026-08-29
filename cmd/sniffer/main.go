package main

import (
	"apb-sniffer/apb"
	"apb-sniffer/crypto"
	"apb-sniffer/logger"
	"apb-sniffer/ue3"
	"log"

	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketStats struct {
	Count int

	// First packet seen for this UDP payload length.
	FirstPayload []byte

	ParsedPackets int
	FailedPackets int

	PacketIDs map[uint32]int
}

type PacketStatsCache struct {
	// UDP payload length -> statistics
	Packets map[int]*PacketStats
}

func NewPacketStatsCache() *PacketStatsCache {
	return &PacketStatsCache{
		Packets: make(map[int]*PacketStats),
	}
}

func (c *PacketStatsCache) Observe(
	payload []byte,
	packetID *uint32,
	parseErr error,
) bool {
	length := len(payload)

	stats, exists := c.Packets[length]

	if !exists {
		stats = &PacketStats{
			FirstPayload: append([]byte(nil), payload...),
			PacketIDs:    make(map[uint32]int),
		}

		c.Packets[length] = stats
	}

	stats.Count++

	if packetID != nil {
		stats.PacketIDs[*packetID]++
	}

	if parseErr == nil {
		stats.ParsedPackets++
	} else {
		stats.FailedPackets++
	}

	return !exists
}

func (c *PacketStatsCache) Lengths() []int {
	result := make([]int, 0, len(c.Packets))

	for length := range c.Packets {
		result = append(result, length)
	}

	sort.Ints(result)

	return result
}

func (c *PacketStatsCache) Dump(appLogger *logger.Logger) {
	appLogger.Debug(
		"========================================",
	)

	appLogger.Debug(
		"Packet statistics",
	)

	appLogger.Debug(
		"========================================",
	)

	for _, length := range c.Lengths() {
		stats := c.Packets[length]

		ids := make([]uint32, 0, len(stats.PacketIDs))

		for id := range stats.PacketIDs {
			ids = append(ids, id)
		}

		sort.Slice(ids, func(i, j int) bool {
			return ids[i] < ids[j]
		})

		packetIDs := ""

		for i, id := range ids {
			if i > 0 {
				packetIDs += ", "
			}

			packetIDs += fmt.Sprintf(
				"%d(%d)",
				id,
				stats.PacketIDs[id],
			)
		}

		appLogger.Debug(
			"%d bytes: count=%d parsed=%d failed=%d packetIDs=[%s]",
			length,
			stats.Count,
			stats.ParsedPackets,
			stats.FailedPackets,
			packetIDs,
		)

		appLogger.Trace(
			"%d bytes first payload:\n%s",
			length,
			hex.Dump(stats.FirstPayload),
		)
	}
}

func resolveDevice(
	devices []pcap.Interface,
	value string,
) (string, error) {
	// Allow:
	//
	// -device 10
	//
	// as well as:
	//
	// -device "\Device\NPF_Loopback"

	if index, err := strconv.Atoi(value); err == nil {
		if index < 0 || index >= len(devices) {
			return "", fmt.Errorf(
				"device index %d out of range",
				index,
			)
		}

		return devices[index].Name, nil
	}

	for _, device := range devices {
		if device.Name == value {
			return device.Name, nil
		}
	}

	return "", fmt.Errorf(
		"device not found: %s",
		value,
	)
}

func main() {
	srcPort := flag.Int(
		"src-port",
		0,
		"UDP source port",
	)

	dstPort := flag.Int(
		"dst-port",
		0,
		"UDP destination port",
	)

	device := flag.String(
		"device",
		"",
		"Network interface/device or device index",
	)

	bidirectional := flag.Bool(
		"bidirectional",
		false,
		"Capture both directions",
	)

	keyHex := flag.String(
		"key",
		"",
		"BTEA key as 32 hexadecimal characters",
	)

	logLevel := flag.String(
		"log-level",
		"info",
		"log level: error, info, debug, trace",
	)

	watchCSA := flag.Bool(
		"watch-csa",
		false,
		"Inspect every packet and print only controller CSA fields 338..345",
	)

	flag.Parse()

	appLogger := logger.New(*logLevel)

	var encryptionKey [16]byte

	if *keyHex != "" {
		keyBytes, err := hex.DecodeString(*keyHex)
		if err != nil {
			log.Fatalf("invalid BTEA key: %v", err)
		}

		if len(keyBytes) != 16 {
			log.Fatalf(
				"BTEA key must be exactly 16 bytes, got %d",
				len(keyBytes),
			)
		}

		copy(encryptionKey[:], keyBytes)

		appLogger.Debug(
			"BTEA session key configured",
		)
	} else {
		appLogger.Debug(
			"BTEA session key not configured",
		)
	}

	if *srcPort == 0 || *dstPort == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// ------------------------------------------------------------
	// Find/select network device
	// ------------------------------------------------------------

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	if len(devices) == 0 {
		log.Fatal("no network interfaces found")
	}

	if *device == "" {
		appLogger.Info("Available interfaces:")

		for i, d := range devices {
			appLogger.Info(
				"[%d] %s",
				i,
				d.Name,
			)

			for _, addr := range d.Addresses {
				appLogger.Info(
					"    %s",
					addr.IP,
				)
			}
		}

		appLogger.Info(
			"Use -device to select an interface.",
		)

		os.Exit(0)
	}

	dev, err := resolveDevice(devices, *device)
	if err != nil {
		log.Fatal(err)
	}

	appLogger.Info(
		"Device: %s",
		dev,
	)

	// ------------------------------------------------------------
	// Open capture
	// ------------------------------------------------------------

	handle, err := pcap.OpenLive(
		dev,
		65535,
		true,
		pcap.BlockForever,
	)

	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	// ------------------------------------------------------------
	// BPF filter
	// ------------------------------------------------------------

	filter := fmt.Sprintf(
		"udp and src port %d and dst port %d",
		*srcPort,
		*dstPort,
	)

	if *bidirectional {
		filter = fmt.Sprintf(
			"udp and ((src port %d and dst port %d) or (src port %d and dst port %d))",
			*srcPort,
			*dstPort,
			*dstPort,
			*srcPort,
		)
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	appLogger.Info(
		"BPF filter: %s",
		filter,
	)

	// ------------------------------------------------------------
	// Packet processing
	// ------------------------------------------------------------

	stats := NewPacketStatsCache()

	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)

	packetSource.NoCopy = false

	// ------------------------------------------------------------
	// Shutdown handling
	// ------------------------------------------------------------

	signals := make(chan os.Signal, 1)

	signal.Notify(
		signals,
		os.Interrupt,
		syscall.SIGTERM,
	)

	appLogger.Info("Listening...")

	go func() {
		<-signals

		appLogger.Info("Stopping...")

		handle.Close()
	}()

	// ------------------------------------------------------------
	// Capture loop
	// ------------------------------------------------------------

	for capturedPacket := range packetSource.Packets() {
		udpLayer := capturedPacket.Layer(
			layers.LayerTypeUDP,
		)

		if udpLayer == nil {
			continue
		}

		udp, ok := udpLayer.(*layers.UDP)

		if !ok {
			continue
		}

		payload := udp.Payload

		if len(payload) == 0 {
			continue
		}

		var uePacket ue3.Packet
		var parseErr error
		decrypted := false
		decryptAttempted := false
		decryptParseErr := error(nil)

		// --------------------------------------------------------
		// In focused CSA mode the capture belongs to an established
		// encrypted session, so prefer BTEA. The ordinary exploratory
		// mode retains its plaintext-first behavior for login traffic.
		// --------------------------------------------------------

		if *watchCSA &&
			*keyHex != "" &&
			len(payload) >= 8 &&
			len(payload)%4 == 0 {

			decryptAttempted = true

			decoded := append(
				[]byte(nil),
				payload...,
			)

			if crypto.BTEADecrypt(
				decoded,
				encryptionKey,
			) {
				decodedPacket, err :=
					ue3.ParsePacket(decoded)

				decryptParseErr = err

				if err == nil {
					uePacket = decodedPacket
					decrypted = true
				}
			}
		}

		if !decrypted {
			uePacket, parseErr = ue3.ParsePacket(payload)
		}

		// In ordinary mode, a failed plaintext parse may be an
		// encrypted packet. Try the configured session key next.
		if parseErr != nil &&
			!decryptAttempted &&
			*keyHex != "" &&
			len(payload) >= 8 &&
			len(payload)%4 == 0 {

			decryptAttempted = true

			decoded := append(
				[]byte(nil),
				payload...,
			)

			if crypto.BTEADecrypt(
				decoded,
				encryptionKey,
			) {
				decodedPacket, err :=
					ue3.ParsePacket(decoded)

				decryptParseErr = err

				if err == nil {
					uePacket = decodedPacket
					parseErr = nil
					decrypted = true
				}
			}
		}

		// --------------------------------------------------------
		// Statistics
		// --------------------------------------------------------

		var packetID *uint32

		if parseErr == nil {
			packetID = &uePacket.PacketID
		}

		isNewLength := stats.Observe(
			payload,
			packetID,
			parseErr,
		)

		// --------------------------------------------------------
		// Parse result
		// --------------------------------------------------------

		if parseErr != nil {
			// Plain parse failure is expected for encrypted packets,
			// so don't report it as ERROR here.
			if decryptAttempted && decryptParseErr != nil {
				appLogger.Debug(
					"UE3 parse failed after BTEA decrypt: length=%d error=%v",
					len(payload),
					decryptParseErr,
				)
			} else {
				appLogger.Debug(
					"UE3 parse failed: length=%d error=%v",
					len(payload),
					parseErr,
				)
			}

			continue
		}

		if decrypted {
			appLogger.Debug(
				"BTEA decrypt + UE3 parse SUCCESS: length=%d packetID=%d",
				len(payload),
				uePacket.PacketID,
			)
		} else {
			appLogger.Debug(
				"Plain UE3 parse SUCCESS: length=%d packetID=%d",
				len(payload),
				uePacket.PacketID,
			)
		}

		if *watchCSA {
			direction := packetDirection(
				uint16(udp.SrcPort),
				uint16(udp.DstPort),
				uint16(*srcPort),
				uint16(*dstPort),
			)

			for i, bunch := range uePacket.Bunches {
				logCSABunch(
					appLogger,
					direction,
					uePacket.PacketID,
					i,
					bunch,
				)
			}

			continue
		}

		// --------------------------------------------------------
		// Ordinary exploratory mode deeply inspects only the first
		// packet of each length. -watch-csa bypasses this cache above.
		// --------------------------------------------------------

		if !isNewLength {
			continue
		}

		appLogger.Debug(
			"NEW LENGTH: %d bytes",
			len(payload),
		)

		appLogger.Debug(
			"PacketID: %d",
			uePacket.PacketID,
		)

		appLogger.Debug(
			"PayloadBits: %d",
			uePacket.PayloadBitCount,
		)

		appLogger.Debug(
			"Bunches: %d",
			len(uePacket.Bunches),
		)

		for i, bunch := range uePacket.Bunches {
			logBunch(
				appLogger,
				i,
				bunch,
			)
		}
	}

	// ------------------------------------------------------------
	// Final statistics
	// ------------------------------------------------------------

	stats.Dump(appLogger)
}

func packetDirection(
	packetSource uint16,
	packetDestination uint16,
	serverPort uint16,
	clientPort uint16,
) string {
	if packetSource == clientPort &&
		packetDestination == serverPort {
		return "C2S"
	}

	if packetSource == serverPort &&
		packetDestination == clientPort {
		return "S2C"
	}

	return fmt.Sprintf(
		"%d->%d",
		packetSource,
		packetDestination,
	)
}

func logCSABunch(
	appLogger *logger.Logger,
	direction string,
	packetID uint32,
	index int,
	bunch ue3.Bunch,
) {
	if bunch.Kind != ue3.BunchData ||
		bunch.ChannelIndex != 2 ||
		bunch.DataBitCount == 0 {
		return
	}

	observation, isCSA, err := apb.DecodeCSA(
		bunch,
		apb.PlayerControllerFieldMax,
	)
	if !isCSA {
		return
	}

	appLogger.Info(
		"CSA %s packet=%d bunch=%d channel=%d seq=%d reliable=%v field=%d name=%s bits=%d indexBits=%d parameterBits=%d raw=%s",
		direction,
		packetID,
		index,
		bunch.ChannelIndex,
		bunch.ChannelSequence,
		bunch.Reliable,
		observation.FieldIndex,
		observation.FieldName,
		bunch.DataBitCount,
		observation.IndexBits,
		observation.ParameterBits,
		hex.EncodeToString(bunch.RawData),
	)

	if err != nil {
		appLogger.Error(
			"CSA %s field=%d decode failed: %v",
			direction,
			observation.FieldIndex,
			err,
		)
		return
	}

	switch observation.FieldIndex {
	case 343:
		target := "absent"
		if observation.TargetPresent {
			targetKind := "netindex"
			if observation.TargetByChannel {
				targetKind = "channel"
			}

			target = fmt.Sprintf(
				"%s:%d",
				targetKind,
				observation.TargetReference,
			)
		}

		appLogger.Info(
			"CSA %s pressed mapping=%d mappingPresent=%v aim=%d aimPresent=%v camera=%g cameraPresent=%v target=%s consumed=%d/%d trailing=%d",
			direction,
			observation.InputMapping,
			observation.InputMappingPresent,
			observation.AimRotation,
			observation.AimRotationPresent,
			observation.CameraCollidePercent,
			observation.CameraPresent,
			target,
			observation.ConsumedBits,
			bunch.DataBitCount,
			observation.TrailingBits,
		)

	case 345:
		appLogger.Info(
			"CSA %s released mapping=%d mappingPresent=%v consumed=%d/%d trailing=%d",
			direction,
			observation.InputMapping,
			observation.InputMappingPresent,
			observation.ConsumedBits,
			bunch.DataBitCount,
			observation.TrailingBits,
		)
	}
}

func logBunch(
	appLogger *logger.Logger,
	index int,
	bunch ue3.Bunch,
) {
	if bunch.Kind == ue3.BunchAck {
		appLogger.Debug(
			"Bunch #%d ACK packet=%d",
			index,
			bunch.AckPacketID,
		)

		return
	}

	appLogger.Debug(
		"Bunch #%d DATA open=%v close=%v reliable=%v channel=%d sequence=%d type=%d bits=%d bytes=%d",
		index,
		bunch.Open,
		bunch.Close,
		bunch.Reliable,
		bunch.ChannelIndex,
		bunch.ChannelSequence,
		bunch.ChannelType,
		bunch.DataBitCount,
		len(bunch.RawData),
	)

	// ------------------------------------------------------------
	// Known controller decoding.
	// ------------------------------------------------------------

	if bunch.ChannelType == 2 {
		fields, err := apb.DecodeControllerFields(
			bunch,
			634,
		)

		if err != nil {
			appLogger.Info(
				"UNKNOWN controller field channel=%d type=%d sequence=%d reliable=%v open=%v close=%v data_bits=%d data_bytes=%d error=%v raw_hex=%s",
				bunch.ChannelIndex,
				bunch.ChannelType,
				bunch.ChannelSequence,
				bunch.Reliable,
				bunch.Open,
				bunch.Close,
				bunch.DataBitCount,
				len(bunch.RawData),
				err,
				hex.EncodeToString(bunch.RawData),
			)

			appLogger.Info(
				"UNKNOWN controller field raw dump:\n%s",
				hex.Dump(bunch.RawData),
			)
		}

		for _, field := range fields {
			if field.Known {
				appLogger.Debug(
					"KNOWN controller field index=%d name=%s begin_bit=%d end_bit=%d",
					field.Index,
					field.Name,
					field.BeginBit,
					field.EndBit,
				)
			} else {
				appLogger.Info(
					"UNKNOWN controller field detail index=%d begin_bit=%d end_bit=%d",
					field.Index,
					field.BeginBit,
					field.EndBit,
				)
			}
		}

		for _, field := range fields {
			if field.Known {
				appLogger.Debug(
					"KNOWN field=%d name=%s bits=%d..%d",
					field.Index,
					field.Name,
					field.BeginBit,
					field.EndBit,
				)

				continue
			}

			appLogger.Info(
				"UNKNOWN channel=%d type=%d reliable=%v open=%v close=%v bits=%d bytes=%d",
				bunch.ChannelIndex,
				bunch.ChannelType,
				bunch.Reliable,
				bunch.Open,
				bunch.Close,
				bunch.DataBitCount,
				len(bunch.RawData),
			)
		}

		if err != nil {
			appLogger.Info(
				"UNKNOWN controller field: channel=%d type=%d error=%v",
				bunch.ChannelIndex,
				bunch.ChannelType,
				err,
			)
		}

		return
	}

	// ------------------------------------------------------------
	// No decoder exists yet for this channel/type.
	// This is intentionally INFO because this is what we're
	// currently investigating.
	// ------------------------------------------------------------

	appLogger.Info(
		"UNKNOWN channel=%d type=%d reliable=%v open=%v close=%v bits=%d bytes=%d",
		bunch.ChannelIndex,
		bunch.ChannelType,
		bunch.Reliable,
		bunch.Open,
		bunch.Close,
		bunch.DataBitCount,
		len(bunch.RawData),
	)

	appLogger.Trace(
		"UNKNOWN channel=%d raw data:\n%s",
		bunch.ChannelIndex,
		hex.Dump(bunch.RawData),
	)
}
