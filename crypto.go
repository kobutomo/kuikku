package main

import (
	"crypto/aes"
	"crypto/cipher"
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
	_, err := io.ReadFull(expand, b)
	if err != nil {
		panic(err)
	}

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
	hkdfLabelBytes, err := hkdfLabel.Bytes()
	if err != nil {
		panic(err)
	}

	return hkdfExpand(secret, hkdfLabelBytes, length)
}

func hkdfExtract(secret, salt []byte) []byte {
	hash := sha256.New
	return hkdf.Extract(hash, secret, salt)
}

func aes128ECBEncrypt(key, plaintext []byte) []byte {
	dst, err := openssl.AesECBEncrypt(plaintext, key, openssl.PKCS7_PADDING)
	if err != nil {
		panic(err)
	}
	return dst
}

// func aes128ECBDecrypt(key, ciphertext []byte) []byte {
// 	dst, _ := openssl.AesECBDecrypt(ciphertext, key, openssl.PKCS7_PADDING)
// 	return dst
// }

func getMask(hpKey, sample []byte) []byte {
	// maskを作成
	return aes128ECBEncrypt(hpKey, sample)[0:5]
}

func decryptAESGCM(key, nonce, aad, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	plaintext, err := aesgcm.Open(nil, nonce, data, aad)
	if err != nil {
		panic(err)
	}
	return plaintext
}
