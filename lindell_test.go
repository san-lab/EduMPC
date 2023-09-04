package main

import (
	"fmt"
	"math/big"
	"testing"
)

func Test_crack(t *testing.T) {
	m := "test"
	priv, pub, x_a, x_b, x_b_enc, X_x, X_y := KeyGenLindell()
	RegularECDSA(m, x_a, x_b, X_x, X_y)
	SignLindell(m, pub, priv, x_a, x_b, x_b_enc, X_x, X_y)
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
