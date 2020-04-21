package tools

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

func EncodeKey(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	privateKeyBase64 := Base64Encode(pemEncoded)
	publicKeyBase64 := Base64Encode(pemEncodedPub)
	return privateKeyBase64, publicKeyBase64
}

func DecodeKey(pemEncoded string, pemEncodedPub string) (privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, err error) {
	var dstPrivate, dstPublic []byte
	dstPrivate, err = Base64Decode(pemEncoded)
	if err != nil {
		return
	}
	dstPublic, err = Base64Decode(pemEncodedPub)
	if err != nil {
		return
	}

	block, _ := pem.Decode(dstPrivate)
	if block == nil {
		err = errors.New("pemEncoded Decode error")
		return
	}
	x509Encoded := block.Bytes
	privateKey, err = x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		return
	}

	blockPub, _ := pem.Decode(dstPublic)
	if blockPub == nil {
		err = errors.New("pemEncodedPub Decode error")
		return
	}
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		return privateKey, publicKey, err
	}
	publicKey = genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey, nil
}

func Base64Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
