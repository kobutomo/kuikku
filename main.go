package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type InitialPacket struct {
	HeaderForm                    uint8
	FixedBit                      uint8
	LongPacketType                uint8
	ReservedBits                  uint8
	PacketNumberLength            uint8
	Version                       []byte
	DestinationConnectionIDLength uint8
	DestinationConnectionID       []byte
	SourceConnectionIDLength      uint8
	SourceConnectionID            []byte
	TokenLength                   uint64
	Token                         []byte
	Length                        uint64
	PacketNumber                  uint64
	PacketPayload                 []byte
	PacketNumberIndex             uint64
}

func (ip InitialPacket) String() string {
	var str = ""
	str += fmt.Sprintf("Header Form: %d\n", ip.HeaderForm)
	str += fmt.Sprintf("Fixed Bit: %d\n", ip.FixedBit)
	str += fmt.Sprintf("Long Packet Type: %d\n", ip.LongPacketType)
	str += fmt.Sprintf("Reserved Bits: %d\n", ip.ReservedBits)
	str += fmt.Sprintf("Packet Number Length: %d\n", ip.PacketNumberLength)
	str += fmt.Sprintf("Version: %d\n", ip.Version)
	str += fmt.Sprintf("Destination Connection ID Length: %d\n", ip.DestinationConnectionIDLength)
	str += fmt.Sprintf("Destination Connection ID: %d\n", ip.DestinationConnectionID)
	str += fmt.Sprintf("Source Connection ID Length: %d\n", ip.SourceConnectionIDLength)
	str += fmt.Sprintf("Source Connection ID: %d\n", ip.SourceConnectionID)
	str += fmt.Sprintf("Token Length: %d\n", ip.TokenLength)
	str += fmt.Sprintf("Token: %s\n", hex.EncodeToString(ip.Token))
	str += fmt.Sprintf("Length: %d byte\n", ip.Length)
	str += fmt.Sprintf("Packet Number: %d\n", ip.PacketNumber)
	str += fmt.Sprintf("Packet Payload: %d\n", ip.PacketPayload)

	return str
}

func main() {
	initialSalt, _ := hex.DecodeString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
	DCID, _ := hex.DecodeString("8394c8f03e515708")

	getKeys(initialSalt, DCID)
	tmpHPKey, _ := hex.DecodeString("9f50449e04a0e810283a1e9933adedd2")
	tmpSample, _ := hex.DecodeString("d1b1c98dd7689fb8ec11d242b123dc9b")

	mask := getMask(tmpHPKey, tmpSample)

	pnIndex := getPNIndexFromRawPacket(input2)
	// mask the header
	input2[0] ^= mask[0] & 0x0f
	input2[pnIndex] ^= mask[1]
	input2[pnIndex+1] ^= mask[2]
	input2[pnIndex+2] ^= mask[3]
	input2[pnIndex+3] ^= mask[4]

	parsedPacket := parsePacket(input2)
	fmt.Println(parsedPacket)

}

func getKeys(initialSalt, DCID []byte) (key, iv, hp []byte) {
	initialSecret := hkdfExtract(initialSalt, DCID)
	clientInitialSecret := hkdfExpandLabel(initialSecret, []byte("client in"), []byte{}, 32)
	key = hkdfExpandLabel(clientInitialSecret, []byte("quic key"), []byte{}, 16)
	iv = hkdfExpandLabel(clientInitialSecret, []byte("quic iv"), []byte{}, 12)
	hp = hkdfExpandLabel(clientInitialSecret, []byte("quic hp"), []byte{}, 16)
	return key, iv, hp
}

func getSampleFromRawPacket(input []byte) []byte {
	// TODO: implement
	return []byte{}
}

func parsePacket(input []byte) InitialPacket {
	/*
		Initial Packet {
			Header Form (1) = 1,
			Fixed Bit (1) = 1,
			Long Packet Type (2) = 0,
			Reserved Bits (2),
			Packet Number Length (2),
			Version (32),
			Destination Connection ID Length (8),
			Destination Connection ID (0..160),
			Source Connection ID Length (8),
			Source Connection ID (0..160),
			Token Length (i),
			Token (..),
			Length (i),
			Packet Number (8..32),
			Packet Payload (8..),
		}
		reference: https://www.rfc-editor.org/rfc/rfc9000#name-initial-packet
	*/
	packet := InitialPacket{}
	var currIndex uint8 = 0
	// input[0] are flags and would be like 1100_1100
	packet.HeaderForm = input[currIndex] >> 7           // 1100_1100 >> 7 = 0000_0001
	packet.FixedBit = (input[currIndex] >> 6) & 1       // 1100_1100 >> 6 = 0000_0011 & 0000_0001 = 0000_0001
	packet.LongPacketType = (input[currIndex] >> 4) & 3 // 1100_1100 >> 4 = 0000_1100 & 0000_0011 = 0000_0000
	packet.ReservedBits = (input[currIndex] >> 2) & 3   // 1100_1100 >> 2 = 0011_0011 & 0000_0011 = 0000_0011
	// see below for the reason why 1 is added to the packet number
	// reference: https://www.rfc-editor.org/rfc/rfc9000#name-1-rtt-packet
	packet.PacketNumberLength = input[currIndex]&3 + 1 // 1100_1100 & 0000_0011 = 0000_0000

	currIndex++
	packet.Version = input[currIndex : currIndex+4]
	currIndex += 4
	packet.DestinationConnectionIDLength = input[currIndex]
	currIndex++
	packet.DestinationConnectionID = input[currIndex : currIndex+packet.DestinationConnectionIDLength]
	currIndex += packet.DestinationConnectionIDLength
	packet.SourceConnectionIDLength = input[currIndex]
	currIndex++
	packet.SourceConnectionID = input[currIndex : currIndex+packet.SourceConnectionIDLength]
	currIndex += packet.SourceConnectionIDLength
	// byte[]
	tokenLengthBytes := getVariableLengthIntegerField(input, currIndex)
	// 0x3f = 0011_1111
	// remove 2 most significant bits
	tokenLengthBytes[0] &= 0x3f
	packet.TokenLength = convertBytesToInteger(tokenLengthBytes)
	currIndex += uint8(len(tokenLengthBytes))
	packet.Token = input[currIndex : currIndex+uint8(packet.TokenLength)]
	currIndex += uint8(packet.TokenLength)
	lengthBytes := getVariableLengthIntegerField(input, currIndex)
	// 0x3f = 0011_1111
	// remove 2 most significant bits
	lengthBytes[0] &= 0x3f
	packet.Length = convertBytesToInteger(lengthBytes)
	currIndex += uint8(len(lengthBytes))
	packet.PacketNumberIndex = uint64(currIndex)
	packetNumberBytes := input[currIndex : currIndex+packet.PacketNumberLength]
	packet.PacketNumber = convertBytesToInteger(packetNumberBytes)
	currIndex += packet.PacketNumberLength
	packet.PacketPayload = input[currIndex:]
	return packet
}

func getPNIndexFromRawPacket(input []byte) int64 {
	packet := InitialPacket{}
	var currIndex uint8 = 0
	currIndex++
	currIndex += 4
	packet.DestinationConnectionIDLength = input[currIndex]
	currIndex++
	currIndex += packet.DestinationConnectionIDLength
	packet.SourceConnectionIDLength = input[currIndex]
	currIndex++
	currIndex += packet.SourceConnectionIDLength
	tokenLengthBytes := getVariableLengthIntegerField(input, currIndex)
	currIndex += uint8(len(tokenLengthBytes))
	currIndex += uint8(convertBytesToInteger(tokenLengthBytes))
	lengthBytes := getVariableLengthIntegerField(input, currIndex)
	currIndex += uint8(len(lengthBytes))
	packet.PacketNumberIndex = uint64(currIndex)
	return int64(currIndex)
}

func getVariableLengthIntegerField(input []byte, currIndex uint8) []byte {
	// reference: https://www.rfc-editor.org/rfc/rfc9000#name-variable-length-integer-enc
	twoMSB := input[currIndex] >> 6
	switch twoMSB {
	case 0:
		return input[currIndex : currIndex+1]
	case 1:
		return input[currIndex : currIndex+2]
	case 2:
		return input[currIndex : currIndex+4]
	case 3:
		return input[currIndex : currIndex+8]
	}

	// never reach here
	return []byte{}
}

func convertBytesToInteger(input []byte) uint64 {
	var ret uint64
	switch len(input) {
	case 1:
		ret = uint64(input[0])
	case 2:
		ret = uint64(int(binary.BigEndian.Uint16(input)))
	case 4:
		ret = uint64(int(binary.BigEndian.Uint32(input)))
	case 8:
		ret = uint64(int(binary.BigEndian.Uint64(input)))
	}
	return ret
}
