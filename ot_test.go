package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func TestPrivKey(t *testing.T) {
	a, x, y, _ := elliptic.GenerateKey(myCurve, rand.Reader)
	fmt.Println("Priv key:", a)
	fmt.Println("length:", len(a))
	fmt.Println("x:", x)
	fmt.Println("y:", y)
	fmt.Println("P:", elliptic.P256().Params().P)
	fmt.Println("N:", elliptic.P256().Params().N)
	fmt.Println("B:", elliptic.P256().Params().B)
	fmt.Println("Gx:", elliptic.P256().Params().Gx)
	fmt.Println("Gy:", elliptic.P256().Params().Gy)
}

func TestSign(t *testing.T) {
	msg := "Hola diego!"
	msg_hash := sha256.Sum256([]byte(msg))

	privK, _ := ecdsa.GenerateKey(myCurve, rand.Reader)
	fmt.Println(privK)

	sig, _ := ecdsa.SignASN1(rand.Reader, privK, msg_hash[:])
	fmt.Println("sig:", sig)

	pubK := privK.Public().(*ecdsa.PublicKey)
	fmt.Println("pubk:", pubK)

	verifies := ecdsa.VerifyASN1(pubK, msg_hash[:], sig)
	fmt.Println(verifies)

	// Simulate format conversions...
	sig_raw := base64.StdEncoding.EncodeToString([]byte(sig))
	fmt.Println("sig_raw:", sig_raw)
	sig, _ = base64.StdEncoding.DecodeString(sig_raw)
	fmt.Println("sig:", sig)

	x_raw := base64.StdEncoding.EncodeToString(pubK.X.Bytes())
	y_raw := base64.StdEncoding.EncodeToString(pubK.Y.Bytes())
	fmt.Println("pubkX_raw:", x_raw)
	fmt.Println("pubkY_raw:", y_raw)
	x_raw2, _ := base64.StdEncoding.DecodeString(x_raw)
	y_raw2, _ := base64.StdEncoding.DecodeString(y_raw)
	x := new(big.Int).SetBytes([]byte(x_raw2))
	y := new(big.Int).SetBytes([]byte(y_raw2))

	pubK = &ecdsa.PublicKey{myCurve, x, y}
	fmt.Println(pubK)

	verifies = ecdsa.VerifyASN1(pubK, msg_hash[:], sig)
	fmt.Println(verifies)

	// Test pubK compression
	//pubK_comp := ubiq_crypto.CompressPubkey(pubK)
	//fmt.Println(pubK_comp)

}

func TestJsSign(t *testing.T) {
	msg := "Hola diego!"
	msg_hash := sha256.Sum256([]byte(msg))

	sig_raw := "tXPaSq/cFi1HvJPC5fEqrFcMDXtB4oX3Gp5AwKlbYyyGpT9jojgNiX5hE9dO9PAbqeawPRMxJ0F1lDqnyFFTWA=="
	sig, _ := base64.StdEncoding.DecodeString(sig_raw)

	x_raw := "641ZBKx1J6OW4wLUqoHy1SEZOZPfisxKAcy3xsZsJ94"
	y_raw := "cCjk8aDFn-bEFez2PJ9Ugui-UwLokENJwFvq70zCN3o"
	x_raw2, _ := base64.StdEncoding.DecodeString(x_raw)
	y_raw2, _ := base64.StdEncoding.DecodeString(y_raw)
	x := new(big.Int).SetBytes([]byte(x_raw2))
	y := new(big.Int).SetBytes([]byte(y_raw2))

	x_hex := []byte("566f0a2365daea1787e2ea34ca1b8a02ed8b24ee643665f49505c62386f4e8bf")
	x_bytes := make([]byte, hex.DecodedLen(len(x_hex)))
	hex.Decode(x_bytes, x_hex)
	fmt.Println(x_bytes)
	fmt.Println(x_raw2)

	y_hex := []byte("8f95a9b3dacea214298602846b936141d6b2cfa69a6b8a3e5727c96ea3e40a4f")
	y_bytes := make([]byte, hex.DecodedLen(len(y_hex)))
	hex.Decode(y_bytes, y_hex)
	fmt.Println(y_bytes)
	fmt.Println(y_raw2)

	pubK := &ecdsa.PublicKey{myCurve, x, y}
	fmt.Println(pubK)

	verifies := ecdsa.VerifyASN1(pubK, msg_hash[:], sig)
	fmt.Println(verifies)
}
