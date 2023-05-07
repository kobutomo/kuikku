package main

import (
	"crypto/sha256"
	"io"

	"github.com/forgoer/openssl"
	"golang.org/x/crypto/cryptobyte"
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
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(ctx)
	})
	hkdfLabelBytes, _ := hkdfLabel.Bytes()

	return hkdfExpand(secret, hkdfLabelBytes, length)
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
