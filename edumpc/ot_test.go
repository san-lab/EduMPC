package edumpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
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
	fmt.Println("len lig:", len(sig))

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

	pubK_bytes, _ := x509.MarshalPKIXPublicKey(pubK)
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubK_bytes,
	}
	pem.Encode(os.Stdout, block)

	verifies = ecdsa.VerifyASN1(pubK, msg_hash[:], sig)
	fmt.Println(verifies)

	// Test pubK compression
	//pubK_comp := ubiq_crypto.CompressPubkey(pubK)
	//fmt.Println(pubK_comp)

}

func TestJsSign(t *testing.T) {
	msg := "hola Diego"
	msg_hash := sha256.Sum256([]byte(msg))
	msg_hash_b64 := base64.StdEncoding.EncodeToString(msg_hash[:])
	fmt.Println("hash:", msg_hash_b64)

	sig_raw := "MEQCIGIfSOrQLb9N1mRtFlwTng4+DTy681W+gVosVkkglxXfAiBxhsMJtEk0Qf+VBArZdPOIJOX8DXVygwmphQDZ/6xQJw=="
	sig, _ := base64.StdEncoding.DecodeString(sig_raw)
	/*
	   	x_raw := "6W8JQY4w0Za+56sZ7h3tJnSsgK4BZBzgexZn8mjdHr4="
	   	y_raw := "HQgcpXDtSu+2gQmsTwSZaUh7IMDKEcrJ50OBgw9K9qY="
	   	x_raw2, _ := base64.StdEncoding.DecodeString(x_raw)
	   	y_raw2, _ := base64.StdEncoding.DecodeString(y_raw)
	   	x := new(big.Int).SetBytes([]byte(x_raw2))
	   	y := new(big.Int).SetBytes([]byte(y_raw2))

	   	// Check base64 vs hex values
	   	x_hex := []byte("e96f09418e30d196bee7ab19ee1ded2674ac80ae01641ce07b1667f268dd1ebe")
	   	x_bytes := make([]byte, hex.DecodedLen(len(x_hex)))
	   	hex.Decode(x_bytes, x_hex)
	   	fmt.Println(x_bytes)
	   	fmt.Println(x_raw2)

	   	y_hex := []byte("1d081ca570ed4aefb68109ac4f049969487b20c0ca11cac9e74381830f4af6a6")
	   	y_bytes := make([]byte, hex.DecodedLen(len(y_hex)))
	   	hex.Decode(y_bytes, y_hex)
	   	fmt.Println(y_bytes)
	   	fmt.Println(y_raw2)

	   	sig_hex := []byte("3045022100fd98dc9bb8724c4862a259dfe5710e03b0fc77fe8778d52028d0a0f9757b8e7f0220259b6d223ca03fe40aca0f7deb2559987bde88c43d964eedb38c6402e44f0659")
	           sig_bytes := make([]byte, hex.DecodedLen(len(sig_hex)))
	           hex.Decode(sig_bytes, sig_hex)
	           fmt.Println(sig_bytes)
	           fmt.Println(sig)
	   	fmt.Println(len(sig))
	   	pubK := &ecdsa.PublicKey{myCurve, x, y}
	   	fmt.Println(pubK)
	*/

	pemPubK := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEl+Y+bhjtEbDCBsRBvBTwogOnbU0y
OeY24w0OhwaLVqSAC91CwgbDWcwkXeWDKjrUEe7lDFOX0vqOGbBETxHNRg==
-----END PUBLIC KEY-----`

	pubKblock, _ := pem.Decode([]byte(pemPubK))
	pubK, err := x509.ParsePKIXPublicKey(pubKblock.Bytes)
	fmt.Println("err:", err)
	verifies := ecdsa.VerifyASN1(pubK.(*ecdsa.PublicKey), msg_hash[:], sig)
	fmt.Println(verifies)
	verifies2 := ecdsa.VerifyASN1(pubK.(*ecdsa.PublicKey), []byte(msg_hash_b64), sig)
	fmt.Println(verifies2)
	verifies3 := ecdsa.VerifyASN1(pubK.(*ecdsa.PublicKey), []byte(msg), sig)
	fmt.Println(verifies3)

	//try with r, s instead
	r_raw := []byte("9ac07cd3b215b272057825237c650bd9c7e963c4ee0fd5de67b56faed4e3e3f5")
	s_raw := []byte("115366ab318067c7035b21405a22d725e9835ed9c6192fc6afebac89bdf338eb")
	r_bytes := make([]byte, hex.DecodedLen(len(r_raw)))
	hex.Decode(r_bytes, r_raw)
	s_bytes := make([]byte, hex.DecodedLen(len(s_raw)))
	hex.Decode(s_bytes, s_raw)

	r := new(big.Int).SetBytes(r_bytes)
	s := new(big.Int).SetBytes(s_bytes)
	verifies0 := ecdsa.Verify(pubK.(*ecdsa.PublicKey), msg_hash[:], r, s)
	fmt.Println(verifies0)

	pubK_bytes, _ := x509.MarshalPKIXPublicKey(pubK)
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubK_bytes,
	}
	pem.Encode(os.Stdout, block)

}
