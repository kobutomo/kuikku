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
	var str = "================== PACKET =====================\n"
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
	pnIndex, sample, dcid := getRemoveHeaderProtectionInfoFromRawPacket(input)
	_, _, hp := getClientKeys(dcid, initialSalt)

	mask := getMask(hp, sample)
	// mask the header
	input[0] ^= mask[0] & 0x0f
	input[pnIndex] ^= mask[1]
	input[pnIndex+1] ^= mask[2]
	input[pnIndex+2] ^= mask[3]
	input[pnIndex+3] ^= mask[4]

	parsedPacket := parsePacket(input)
	fmt.Printf("pnIndex: %d\n", pnIndex)
	fmt.Printf("sample: %x\n", sample)
	fmt.Printf("mask: %x\n", mask)
	fmt.Println(parsedPacket)

}

// the keys protecting the client packets
func getClientKeys(dcid, initialSalt []byte) (quicKey, quicIV, quicHP []byte) {
	initialSecret := hkdfExtract(dcid, initialSalt)
	clientInitialSecret := hkdfExpandLabel(initialSecret, []byte("client in"), []byte{}, 32)
	quicKey = hkdfExpandLabel(clientInitialSecret, []byte("quic key"), []byte{}, 16)
	quicIV = hkdfExpandLabel(clientInitialSecret, []byte("quic iv"), []byte{}, 12)
	quicHP = hkdfExpandLabel(clientInitialSecret, []byte("quic hp"), []byte{}, 16)
	fmt.Printf("dcid: %x\n", dcid)
	fmt.Printf("initialSecret: %x\n", initialSecret)
	fmt.Printf("clientInitialSecret: %x\n", clientInitialSecret)
	fmt.Printf("quicKey: %x\n", quicKey)
	fmt.Printf("quicIV: %x\n", quicIV)
	fmt.Printf("quicHP: %x\n", quicHP)
	return quicKey, quicIV, quicHP
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
	var currIndex uint16 = 0
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
	packet.DestinationConnectionID = input[currIndex : currIndex+uint16(packet.DestinationConnectionIDLength)]
	currIndex += uint16(packet.DestinationConnectionIDLength)
	packet.SourceConnectionIDLength = input[currIndex]
	currIndex++
	packet.SourceConnectionID = input[currIndex : currIndex+uint16(packet.SourceConnectionIDLength)]
	currIndex += uint16(packet.SourceConnectionIDLength)
	// byte[]
	tokenLengthBytes := getVariableLengthIntegerField(input, currIndex)
	// 0x3f = 0011_1111
	// remove 2 most significant bits
	tokenLengthBytes[0] &= 0x3f
	packet.TokenLength = convertBytesToInteger(tokenLengthBytes)
	currIndex += uint16(len(tokenLengthBytes))
	packet.Token = input[currIndex : currIndex+uint16(packet.TokenLength)]
	currIndex += uint16(packet.TokenLength)
	lengthBytes := getVariableLengthIntegerField(input, currIndex)
	// 0x3f = 0011_1111
	// remove 2 most significant bits
	lengthBytes[0] &= 0x3f
	packet.Length = convertBytesToInteger(lengthBytes)
	currIndex += uint16(len(lengthBytes))
	packet.PacketNumberIndex = uint64(currIndex)
	packetNumberBytes := input[currIndex : currIndex+uint16(packet.PacketNumberLength)]
	packet.PacketNumber = convertBytesToInteger(packetNumberBytes)
	currIndex += uint16(packet.PacketNumberLength)
	// this if statement is for debugging
	if uint64(len(input[currIndex:])) > packet.Length-uint64(packet.PacketNumberLength) {
		packet.PacketPayload = input[currIndex : currIndex+uint16(packet.Length)-uint16(packet.PacketNumberLength)]
	} else {
		packet.PacketPayload = input[currIndex:]
	}
	return packet
}

func getRemoveHeaderProtectionInfoFromRawPacket(input []byte) (pnIndex int64, sample, dcid []byte) {
	const sampleLength = 16
	var currIndex uint16 = 0
	currIndex++
	currIndex += 4
	destinationConnectionIDLength := input[currIndex]
	currIndex++
	dcid = input[currIndex : currIndex+uint16(destinationConnectionIDLength)]
	currIndex += uint16(destinationConnectionIDLength)
	sourceConnectionIDLength := input[currIndex]
	currIndex++
	currIndex += uint16(sourceConnectionIDLength)
	tokenLengthBytes := getVariableLengthIntegerField(input, currIndex)
	currIndex += uint16(len(tokenLengthBytes))
	currIndex += uint16(convertBytesToInteger(tokenLengthBytes))
	lengthBytes := getVariableLengthIntegerField(input, currIndex)
	currIndex += uint16(len(lengthBytes))
	sampleStartIndex := currIndex + 4
	sample = input[sampleStartIndex : sampleStartIndex+sampleLength]
	return int64(currIndex), sample, dcid
}

func getVariableLengthIntegerField(input []byte, currIndex uint16) []byte {
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
