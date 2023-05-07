package main

import "encoding/binary"

func getVariableLengthIntegerField(input []byte, currIndex uint64) []byte {
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

// input1 and input2 must have the same length
func byteXOR(input1, input2 []byte) []byte {
	ret := make([]byte, len(input1))
	for i := range input1 {
		ret[i] = input1[i] ^ input2[i]
	}
	return ret
}
