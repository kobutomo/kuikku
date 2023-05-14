package tls13

import (
	"encoding/binary"
	"fmt"
)

type clientHello struct {
	protocolVersion    uint16
	random             []byte
	legacySessionID    []byte
	cipherSuites       [][]byte
	compressionMethods []byte
	extensions         []byte
}

func (ch clientHello) String() string {
	str := ""
	str += fmt.Sprintf("protocolVersion: %#04x\n", ch.protocolVersion)
	str += fmt.Sprintf("random: %#x\n", ch.random)
	str += fmt.Sprintf("legacySessionID: %02d\n", ch.legacySessionID)
	str += fmt.Sprintf("cipherSuites: %#x\n", ch.cipherSuites)
	str += fmt.Sprintf("compressionMethods: %02d\n", ch.compressionMethods)
	str += fmt.Sprintf("extensions: %#x\n", ch.extensions)
	return str
}

func (c *clientHello) Unmarshal(input []byte) {
	currentIndex := uint64(0)
	// 0303
	c.protocolVersion = uint16(input[currentIndex])<<8 | uint16(input[currentIndex+1])
	currentIndex += 2
	// 79c73849e8e5ceb8e76676c51f3ffa2b36b2af31246f3d4fc84654a0e309954e
	c.random = input[currentIndex : currentIndex+32]
	currentIndex += 32
	// this client does not support session resumption
	c.legacySessionID = input[currentIndex : currentIndex+1]
	currentIndex += 1
	cipherSuitesLen := binary.BigEndian.Uint16(input[currentIndex : currentIndex+2])
	currentIndex += 2
	c.cipherSuites = make([][]byte, cipherSuitesLen/2)
	for i := range c.cipherSuites {
		c.cipherSuites[i] = input[currentIndex : currentIndex+2]
		currentIndex += 2
	}
	compressionMethodsLen := uint64(input[currentIndex])
	currentIndex += 1
	c.compressionMethods = input[currentIndex : currentIndex+compressionMethodsLen]
}
