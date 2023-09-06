package edumpc

import (
	//	"fmt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
)

// Messages only known by sender
var m0_test = []byte("boring_message00000")
var m1_test = []byte("another_boring_message11111")

type ECPoint struct {
	X *big.Int `json:"x"`
	Y *big.Int `json:"y"`
}

// Public information
var myCurve = elliptic.P256()

// Generate private a, and sends public A = aG
func senderInit(curve elliptic.Curve) (*ECPoint, []byte, error) {
	a, aGx, aGy, err := elliptic.GenerateKey(curve, rand.Reader)
	A := ECPoint{X: aGx, Y: aGy}
	return &A, a, err
}

// Takes A from sender, generates private b, and sends either B = bG or B = A + bG depending on its message choice (c = 0 or c = 1)
func receiverPicks(curve elliptic.Curve, A *ECPoint, c int) (*ECPoint, []byte, error) {
	b, bGx, bGy, err := elliptic.GenerateKey(curve, rand.Reader)

	Bx, By := bGx, bGy
	if c == 2 {
		Bx, By = curve.Add(A.X, A.Y, bGx, bGy)
	}

	B := ECPoint{X: Bx, Y: By}
	return &B, b, err
}

// Ciphers both messages, each with a different key depending on its own a, A and receiver's B
func senderEncrypts(curve elliptic.Curve, A *ECPoint, B *ECPoint, a []byte, m0 []byte, m1 []byte) ([]byte, []byte, []byte, []byte, error) {
	// m0 encryption
	aBx, aBy := curve.ScalarMult(B.X, B.Y, a)
	// hash sha256 as encryption key
	k0 := sha256.Sum256(append(aBx.Bytes(), aBy.Bytes()...))
	// encrypt with aes256
	e0, nonce0, err := EncryptAES(k0[:], m0)

	// m1 encryption
	minusA := opposite(curve, A)
	BminusAx, BminusAy := curve.Add(B.X, B.Y, minusA.X, minusA.Y)
	aBminusAx, aBminusAy := curve.ScalarMult(BminusAx, BminusAy, a)
	// hash sha256 as encryption key
	k1 := sha256.Sum256(append(aBminusAx.Bytes(), aBminusAy.Bytes()...))
	// encrypt with aes256
	e1, nonce1, err := EncryptAES(k1[:], m1)

	//	fmt.Println("k0: ", k0)
	//	fmt.Println("k1: ", k1)
	return e0, nonce0, e1, nonce1, err
}

// Tries to decrypt both messages with a key formed with its own b and sender's A. Will only be able to decrypt one
func receiverDecrypts(curve elliptic.Curve, A *ECPoint, b []byte, e0 []byte, nonce0 []byte, e1 []byte, nonce1 []byte) ([]byte, error) {
	bAx, bAy := curve.ScalarMult(A.X, A.Y, b)
	// hash sha256 as decryption key
	kc := sha256.Sum256(append(bAx.Bytes(), bAy.Bytes()...))

	//	fmt.Println("kc: ", kc)

	// can only decrypt one of them
	m0, err := DecryptAES(kc[:], nonce0, e0)
	if err == nil {
		return m0, err
	}
	m1, err := DecryptAES(kc[:], nonce1, e1)
	if err == nil {
		return m1, err
	}
	return []byte{}, err
}

// Opposite of a elliptic curve point, to compute B + (-A)
func opposite(curve elliptic.Curve, A *ECPoint) *ECPoint {
	// Opposite of A (which is same x and opposite y coordinate, and we also need to take modulo because the .Add method wont work with negative number)
	minusAy := big.NewInt(0).Mod(big.NewInt(0).Neg(A.Y), curve.Params().P)
	minusA := ECPoint{X: A.X, Y: minusAy}
	return &minusA
}

func EncryptAES(key []byte, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte{}, []byte{}, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, err
}

func DecryptAES(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return []byte{}, err
	}
	return plaintext, err
}
