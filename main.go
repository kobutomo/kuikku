package main

import (
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
	PacketNumber                  []byte
	PacketPayload                 []byte
	PacketNumberIndex             uint64
	RawHeader                     []byte
}

func (ip InitialPacket) String() string {
	var str = "================== PACKET =====================\n"
	str += "------------------- HEADER -------------------\n"
	str += fmt.Sprintf("Header Form: %d\n", ip.HeaderForm)
	str += fmt.Sprintf("Fixed Bit: %d\n", ip.FixedBit)
	str += fmt.Sprintf("Long Packet Type: %d\n", ip.LongPacketType)
	str += fmt.Sprintf("Reserved Bits: %d\n", ip.ReservedBits)
	str += fmt.Sprintf("Packet Number Length: %d\n", ip.PacketNumberLength)
	str += fmt.Sprintf("Version: %d\n", convertBytesToInteger(ip.Version))
	str += fmt.Sprintf("Destination Connection ID Length: %d\n", ip.DestinationConnectionIDLength)
	str += fmt.Sprintf("Destination Connection ID: %x\n", ip.DestinationConnectionID)
	str += fmt.Sprintf("Source Connection ID Length: %d\n", ip.SourceConnectionIDLength)
	str += fmt.Sprintf("Source Connection ID: %x\n", ip.SourceConnectionID)
	str += fmt.Sprintf("Token Length: %d\n", ip.TokenLength)
	str += fmt.Sprintf("Token: %s\n", hex.EncodeToString(ip.Token))
	str += fmt.Sprintf("Length: %d byte\n", ip.Length)
	str += fmt.Sprintf("Packet Number: %d\n", convertBytesToInteger(ip.PacketNumber))
	str += "------------------ PAYLOAD ------------------\n"
	str += fmt.Sprintf("%x\n", ip.PacketPayload)

	return str
}

func main() {
	sampleImput := input3
	initialSalt, _ := hex.DecodeString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
	pnIndex, sample, dcid := getRemoveHeaderProtectionInfoFromRawPacket(sampleImput)
	clientKey, clientIV, clientHP := getClientKeys(dcid, initialSalt)

	mask := getMask(clientHP, sample)
	removeHeaderProtection(sampleImput, mask, pnIndex)

	parsedPacket := parsePacket(sampleImput)
	fmt.Printf("pnIndex: %d\n", pnIndex)
	fmt.Printf("sample: %x\n", sample)
	fmt.Printf("mask: %x\n", mask)
	fmt.Println(parsedPacket)
	decryptedPacket := decryptPayload(parsedPacket.RawHeader, parsedPacket.PacketPayload, clientIV, clientKey, parsedPacket.PacketNumber)
	fmt.Println("============= Decrypted Payload =============")
	fmt.Printf("Hex: %x\n", decryptedPacket)
	fmt.Printf("String: %s\n", decryptedPacket)
}

// this changes the input
func removeHeaderProtection(input, mask []byte, pnIndex uint64) {
	fmt.Println("============= Removing Header Protection =============")
	input[0] ^= mask[0] & 0x0f
	packetNumberLength := input[0]&0x03 + 1
	input[pnIndex] ^= mask[1]
	if packetNumberLength < 2 {
		return
	}
	input[pnIndex+1] ^= mask[2]
	if packetNumberLength < 3 {
		return
	}
	input[pnIndex+2] ^= mask[3]
	if packetNumberLength < 4 {
		return
	}
	input[pnIndex+3] ^= mask[4]
}

func decryptPayload(header, payload, clientIV, clientKey, packetNumberBytes []byte) []byte {
	fmt.Println("============= Decrypting Payload =============")
	lengthDiff := len(clientIV) - len(packetNumberBytes)
	padding := make([]byte, lengthDiff)
	fixedPNB := append(padding, packetNumberBytes...)
	nonce := byteXOR(fixedPNB, clientIV)
	aad := header
	data := payload
	plaintext := decryptAESGCM(clientKey, nonce, aad, data)
	fmt.Printf("nonce: %x\n", nonce)
	fmt.Printf("aad: %x\n", aad)
	fmt.Printf("data: %x\n", data)
	return plaintext
}

// the keys protecting the client packets
func getClientKeys(dcid, initialSalt []byte) (clientKey, clientIV, clientHP []byte) {
	fmt.Println("============= Generating Client Keys =============")
	initialSecret := hkdfExtract(dcid, initialSalt)
	clientInitialSecret := hkdfExpandLabel(initialSecret, []byte("client in"), []byte{}, 32)
	clientKey = hkdfExpandLabel(clientInitialSecret, []byte("quic key"), []byte{}, 16)
	clientIV = hkdfExpandLabel(clientInitialSecret, []byte("quic iv"), []byte{}, 12)
	clientHP = hkdfExpandLabel(clientInitialSecret, []byte("quic hp"), []byte{}, 16)
	fmt.Printf("dcid: %x\n", dcid)
	fmt.Printf("initialSecret: %x\n", initialSecret)
	fmt.Printf("clientInitialSecret: %x\n", clientInitialSecret)
	fmt.Printf("clientKey: %x\n", clientKey)
	fmt.Printf("clientIV: %x\n", clientIV)
	fmt.Printf("clientHP: %x\n", clientHP)
	return clientKey, clientIV, clientHP
}

func parsePacket(input []byte) InitialPacket {
	// Initial Packet {
	// 	Header Form (1) = 1,
	// 	Fixed Bit (1) = 1,
	// 	Long Packet Type (2) = 0,
	// 	Reserved Bits (2),
	// 	Packet Number Length (2),
	// 	Version (32),
	// 	Destination Connection ID Length (8),
	// 	Destination Connection ID (0..160),
	// 	Source Connection ID Length (8),
	// 	Source Connection ID (0..160),
	// 	Token Length (i),
	// 	Token (..),
	// 	Length (i),
	// 	Packet Number (8..32),
	// 	Packet Payload (8..),
	// }
	// reference: https://www.rfc-editor.org/rfc/rfc9000#name-initial-packet
	packet := InitialPacket{}
	var currIndex uint64 = 0
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
	packet.DestinationConnectionID = input[currIndex : currIndex+uint64(packet.DestinationConnectionIDLength)]
	currIndex += uint64(packet.DestinationConnectionIDLength)
	packet.SourceConnectionIDLength = input[currIndex]
	currIndex++
	packet.SourceConnectionID = input[currIndex : currIndex+uint64(packet.SourceConnectionIDLength)]
	currIndex += uint64(packet.SourceConnectionIDLength)
	// byte[]
	tokenLengthBytes := getVariableLengthIntegerField(input, currIndex)
	// 0x3f = 0011_1111
	// remove 2 most significant bits
	cpTokenLengthBytes := make([]byte, len(tokenLengthBytes))
	copy(cpTokenLengthBytes, tokenLengthBytes)
	cpTokenLengthBytes[0] &= 0x3f
	packet.TokenLength = convertBytesToInteger(cpTokenLengthBytes)
	currIndex += uint64(len(tokenLengthBytes))
	packet.Token = input[currIndex : currIndex+uint64(packet.TokenLength)]
	currIndex += uint64(packet.TokenLength)
	lengthBytes := getVariableLengthIntegerField(input, currIndex)
	// 0x3f = 0011_1111
	// remove 2 most significant bits
	cpLengthBytes := make([]byte, len(lengthBytes))
	copy(cpLengthBytes, lengthBytes)
	cpLengthBytes[0] &= 0x3f
	packet.Length = convertBytesToInteger(cpLengthBytes)
	currIndex += uint64(len(lengthBytes))
	packet.PacketNumberIndex = uint64(currIndex)
	packetNumberBytes := input[currIndex : currIndex+uint64(packet.PacketNumberLength)]
	packet.PacketNumber = packetNumberBytes
	currIndex += uint64(packet.PacketNumberLength)
	packet.RawHeader = input[:currIndex]
	// this if statement is for debugging
	if uint64(len(input[currIndex:])) > packet.Length-uint64(packet.PacketNumberLength) {
		packet.PacketPayload = input[currIndex : currIndex+uint64(packet.Length)-uint64(packet.PacketNumberLength)]
	} else {
		packet.PacketPayload = input[currIndex:]
	}
	return packet
}

func getRemoveHeaderProtectionInfoFromRawPacket(input []byte) (pnIndex uint64, sample, dcid []byte) {
	const sampleLength = 16
	var currIndex uint64 = 0
	currIndex++
	currIndex += 4
	destinationConnectionIDLength := input[currIndex]
	currIndex++
	dcid = input[currIndex : currIndex+uint64(destinationConnectionIDLength)]
	currIndex += uint64(destinationConnectionIDLength)
	sourceConnectionIDLength := input[currIndex]
	currIndex++
	currIndex += uint64(sourceConnectionIDLength)
	tokenLengthBytes := getVariableLengthIntegerField(input, currIndex)
	currIndex += uint64(len(tokenLengthBytes))
	currIndex += uint64(convertBytesToInteger(tokenLengthBytes))
	lengthBytes := getVariableLengthIntegerField(input, currIndex)
	currIndex += uint64(len(lengthBytes))
	sampleStartIndex := currIndex + 4
	sample = make([]byte, sampleLength)
	copy(sample, input[sampleStartIndex:sampleStartIndex+sampleLength])
	return uint64(currIndex), sample, dcid
}
