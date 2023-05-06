package main

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/forgoer/openssl"
	"golang.org/x/crypto/hkdf"
)

func hkdfExpand(secret, hkdflabel []byte, length uint16) []byte {
	hash := sha256.New
	expand := hkdf.Expand(hash, secret, hkdflabel)
	b := make([]byte, length)
	io.ReadFull(expand, b)

	return b
}

func hkdfExpandLabel(secret, label, ctx []byte, length uint16) []byte {
	// create label
	// add prefix
	tlslabel := []byte(`tls13 `)
	tlslabel = append(tlslabel, label...)
	// add length
	hkdflabel := make([]byte, 2)
	binary.BigEndian.PutUint16(hkdflabel, length)
	hkdflabel = append(hkdflabel, byte(len(tlslabel)))
	hkdflabel = append(hkdflabel, tlslabel...)
	hkdflabel = append(hkdflabel, byte(len(ctx)))
	hkdflabel = append(hkdflabel, ctx...)

	return hkdfExpand(secret, hkdflabel, length)
}

func hkdfExtract(secret, salt []byte) []byte {
	hash := sha256.New
	return hkdf.Extract(hash, secret, salt)
}

func aes128ECBEncrypt(key, plaintext []byte) []byte {
	dst, _ := openssl.AesECBEncrypt(plaintext, key, openssl.PKCS7_PADDING)
	return dst
}

func aes128ECBDecrypt(key, ciphertext []byte) []byte {
	dst, _ := openssl.AesECBDecrypt(ciphertext, key, openssl.PKCS7_PADDING)
	return dst
}

func getMask(hpKey, sample []byte) []byte {
	// maskを作成
	return aes128ECBEncrypt(hpKey, sample)[0:5]
}
