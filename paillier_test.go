package main

import (
	"fmt"
	"math/big"
	"testing"
)

func TestProof(t *testing.T) {
	priv, _ := GenerateNiceKeyPair(1024)
	x := big.NewInt(173)
	fmt.Println("gcd:", new(big.Int).GCD(nil, nil, priv.N, priv.Lam))
	y := SQFProof(priv.Lam, priv.N, x, false)
	yn := new(big.Int).Exp(y, priv.N, priv.N)
	fmt.Println("yn:", yn)
}

func TestBadProof(t *testing.T) {
	priv, _, ps, qs := GenerateAttackKey(1024)
	x := big.NewInt(173)
	lambda := big.NewInt(1)
	pt := big.NewInt(1)
	for _, p := range ps {
		pm1 := new(big.Int).Sub(p, One)
		lambda.Mul(lambda, pm1)
		pt.Mul(pt, p)
	}
	for _, q := range qs {
		qm1 := new(big.Int).Sub(q, One)
		lambda.Mul(lambda, qm1)
	}
	fmt.Println(lambda, priv.N, x)
	fmt.Println("gcd2:", new(big.Int).GCD(nil, nil, priv.N, lambda))

	fmt.Println("pt:", pt)
	y := SQFProof(lambda, priv.N, x, true)
	yn := new(big.Int).Exp(y, priv.N, priv.N)
	fmt.Println("yn2:", yn)
}

func TestProof2(t *testing.T) {
	fmt.Println("----------------")
	priv, _ := GenerateNiceKeyPair(1024)
        x := big.NewInt(173)
	r := PPPProof(x, priv.N)
	fmt.Println("r:", r)
	r2 := new(big.Int).Exp(r, big.NewInt(2), priv.N)
	fmt.Println("r2:", r2)

	minusX := new(big.Int).Mod(new(big.Int).Neg(x), priv.N)
	twox := new(big.Int).Add(x, x)
	minustwox := new(big.Int).Mod(new(big.Int).Add(minusX, minusX), priv.N)
	fmt.Println(r2.Cmp(x), r2.Cmp(minusX), r2.Cmp(twox), r2.Cmp(minustwox))
	fmt.Println("P mod 8: ", new(big.Int).Mod(priv.P, big.NewInt(8)))
	fmt.Println("Q mod 8: ", new(big.Int).Mod(priv.P, big.NewInt(8)))
	fmt.Println("P-Q mod 8: ", new(big.Int).Mod(new(big.Int).Add(priv.P, new(big.Int).Neg(priv.Q)), big.NewInt(8)))
}
