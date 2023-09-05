package edumpc

import (
	"fmt"
	"math/big"
	"testing"
)

func TestHonestExecution(t *testing.T) {
	m := "test"
	paillier_bits := 1024
	x_a := big.NewInt(33)
	x_b := big.NewInt(98)
	k_a := big.NewInt(44)
	k_b := big.NewInt(87)
	attack := false
	l := big.NewInt(0)
	y_b := big.NewInt(0)

	priv, pub, x_a, x_b, x_b_enc, X_x, X_y := KeyGenLindell(x_a, x_b, paillier_bits)
	//RegularECDSA(m, x_a, x_b, X_x, X_y)
	SignLindell(m, pub, priv, x_a, x_b, x_b_enc, X_x, X_y, k_a, k_b, attack, l, y_b)
}

func TestCrack(t *testing.T) {
	attack := true
	m := "test"
	paillier_bits := 2048
	x_a := big.NewInt(33)
	x_b := big.NewInt(10234)
	k_b := big.NewInt(86)

	l := big.NewInt(1)
	k_a := new(big.Int).Exp(big.NewInt(2), l, nil) // Nonce A must be 2^l
	y_b := big.NewInt(0)

	priv, pub, x_a, x_b, x_b_enc, X_x, X_y := KeyGenLindell(x_a, x_b, paillier_bits)
	SignLindell(m, pub, priv, x_a, x_b, x_b_enc, X_x, X_y, k_a, k_b, attack, l, y_b)
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
