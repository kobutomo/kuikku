package tls13

import (
	"fmt"
)

const (
	HandshakeTypeClientHello uint8 = 0x01
	HandshakeTypeServerHello uint8 = 0x02
	// ...
)

type Handshake struct {
	HandshakeType uint8
	Length        uint32
	ClientHello   clientHello
}

func (h *Handshake) Unmarshal(input []byte) {
	h.HandshakeType = input[0]
	// 00 01 04
	h.Length = uint32(input[3]) | uint32(input[2])<<8 | uint32(input[1])<<16
	if h.HandshakeType == HandshakeTypeClientHello {
		h.ClientHello.Unmarshal(input[4:])
	}
}

func (h Handshake) String() string {
	str := ""
	str += fmt.Sprintf("HandshakeType: %d\n", h.HandshakeType)
	str += fmt.Sprintf("Length: %d\n", h.Length)
	if h.HandshakeType == HandshakeTypeClientHello {
		str += h.ClientHello.String()
	}
	return str
}
