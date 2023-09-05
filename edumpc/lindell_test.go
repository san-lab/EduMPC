package edumpc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
)

func TestHonestExecution(t *testing.T) {
	paillier_bits := 1024
	m := "test"
	m_hash := sha256.Sum256([]byte(m))

	x_a := big.NewInt(33)
	x_b := big.NewInt(98)
	k_a := big.NewInt(44)
	k_b := big.NewInt(87)

	attack := false
	l := big.NewInt(0)
	y_b := big.NewInt(0)

	priv, pub, x_b_enc, edcsaPubKey := KeyGenLindell(x_a, x_b, paillier_bits)
	r, s := SignLindell(m, pub, priv, x_a, x_b, x_b_enc, k_a, k_b, attack, l, y_b)
	fmt.Println("Verifies?", ecdsa.Verify(edcsaPubKey, m_hash[:], r, s))
}

func TestFullCrack(t *testing.T) {
	paillier_bits := 1024
	m := "test"
	m_hash := sha256.Sum256([]byte(m))

	attack := true

	x_a := big.NewInt(33)
	x_b, _ := rand.Int(rand.Reader, big.NewInt(1000))
	fmt.Println("x_b:", x_b)
	k_b, _ := rand.Int(rand.Reader, big.NewInt(100000000))

	priv, pub, x_b_enc, ecdsaPubKey := KeyGenLindell(x_a, x_b, paillier_bits)

	l := big.NewInt(1)
	y_b := big.NewInt(0)
	bitstring := ""
	for i := 0; i < x_b.BitLen(); i++ {
		k_a := new(big.Int).Exp(big.NewInt(2), l, nil)

		r, s := SignLindell(m, pub, priv, x_a, x_b, x_b_enc, k_a, k_b, attack, l, y_b)
		verifies := ecdsa.Verify(ecdsaPubKey, m_hash[:], r, s)

		if !verifies {
			bitstring = "1" + bitstring
			fmt.Println("1")
			inc_y_b := new(big.Int).Div(k_a, big.NewInt(2))
			y_b.Add(y_b, inc_y_b)
		} else {
			bitstring = "0" + bitstring
			fmt.Println("0")
		}
		l.Add(l, big.NewInt(1))
	}
	fmt.Println("Bits:", bitstring)
	fmt.Println("Share of b:", y_b)

}

func Test1BitCrack(t *testing.T) {
	paillier_bits := 1024
	m := "test"
	m_hash := sha256.Sum256([]byte(m))

	attack := true

	x_a := big.NewInt(33)
	x_b, _ := rand.Int(rand.Reader, big.NewInt(100000000))
	fmt.Println("x_b:", x_b)
	k_b, _ := rand.Int(rand.Reader, big.NewInt(100000000))

	priv, pub, x_b_enc, ecdsaPubKey := KeyGenLindell(x_a, x_b, paillier_bits)

	l := big.NewInt(1)
	y_b := big.NewInt(0)
	k_a := new(big.Int).Exp(big.NewInt(2), l, nil) // Nonce A must be 2^l

	r, s := SignLindell(m, pub, priv, x_a, x_b, x_b_enc, k_a, k_b, attack, l, y_b)
	verifies := ecdsa.Verify(ecdsaPubKey, m_hash[:], r, s)
	fmt.Println("Verifies?", verifies)
	if !verifies {
		fmt.Println("Secret share is odd")
	} else {
		fmt.Println("Secret share is even")
	}
}

func TestHomomorphic(t *testing.T) {
	priv, pub := GenerateNiceKeyPair(32)
	fmt.Println("priv:", priv)
	fmt.Println("pub:", pub)

	value := big.NewInt(123)
	value_enc := pub.Encrypt(value)
	value_dec := priv.Decrypt(value_enc)
	fmt.Println(value_dec)

	value2 := big.NewInt(2)
	value2_enc := pub.Encrypt(value2)

	value3_enc := new(big.Int).Mul(value_enc, value2_enc) // Enc(a) * Enc(b) = Enc(a + b)
	value3 := priv.Decrypt(value3_enc)
	fmt.Println(value3)

	value4 := big.NewInt(3)
	value5_enc := new(big.Int).Exp(value3_enc, value4, nil) // Enc(a)^b = Enc(b * a)
	value5 := priv.Decrypt(value5_enc)
	fmt.Println(value5)
}
