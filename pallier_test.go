package main

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestEncDec(t *testing.T) {
	pr, pub := GenerateNiceKeyPair(256)
	for i := 100; i > 0; i-- {
		pt1, _ := rand.Int(rand.Reader, pr.N)
		pt2, _ := rand.Int(rand.Reader, pr.N)
		//fmt.Println(pt1, pt2)
		ct1 := pub.Encrypt(pt1)
		dt1 := pr.Decrytpt(ct1)
		if dt1.Cmp(pt1) != 0 {
			t.Error("Decryption unsuccessful!")
		}
		ct2 := pub.Encrypt(pt2)
		dt2 := pr.Decrytpt(ct2)
		if dt2.Cmp(pt2) != 0 {
			t.Error("Decryption unsuccessful!")
		}

		cmul := new(big.Int).Mul(ct1, ct2)
		dadd := pr.Decrytpt(cmul)
		if !pub.EqModN(new(big.Int).Add(pt1, pt2), dadd) {
			t.Error("Homomorphic addition broken!")
		}

		cpow := new(big.Int).Exp(ct1, pt2, pr.N2)
		if !pub.EqModN(new(big.Int).Mul(pt1, pt2), pr.Decrytpt(cpow)) {
			t.Error("Scalar multipilcation nothomomorphic")
		}

	}

}
