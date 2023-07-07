package edumpc

import (
	"crypto/rand"
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
	fmt.Println("x:", x)
}

func TestBadProof(t *testing.T) {
	fmt.Println("----------------")
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
	fmt.Println("gcd:", new(big.Int).GCD(nil, nil, priv.N, lambda))
	fmt.Println("pt:", pt)

	y := SQFProof(lambda, priv.N, x, true) // Not coprime, cant compute well
	yn := new(big.Int).Exp(y, priv.N, priv.N)
	fmt.Println("yn:", yn)
}

func TestProof2(t *testing.T) {
	fmt.Println("----------------")
	priv, _ := GenerateNiceKeyPair(256)
	x, _ := rand.Int(rand.Reader, priv.N)
	sq, sq2, i, ok := PPPProof(x, priv.P, priv.Q)
	sq2.Mod(sq2, priv.N)
	fmt.Println("Proof exists:", ok)

	if ok {
		fmt.Println("i:", i)
		v := new(big.Int)
		v.Exp(sq, big.NewInt(2), priv.N)
		fmt.Println("v:", v)
		fmt.Println("sq2:", sq2)
		if sq2.Sub(sq2, v).Mod(sq2, priv.N).Cmp(Zero) != 0 {
			fmt.Println("Wrong square")
		}
	}
	fmt.Println("P:", priv.P)
	fmt.Println("Q:", priv.Q)

	fmt.Println("P mod 8: ", new(big.Int).Mod(priv.P, Eight))
	fmt.Println("Q mod 8: ", new(big.Int).Mod(priv.Q, Eight))
	fmt.Println("P-Q mod 8: ", new(big.Int).Mod(new(big.Int).Add(priv.P, new(big.Int).Neg(priv.Q)), Eight))
}
