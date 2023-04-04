package main

import (
//	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
)

func TestProofSQF(t *testing.T) {
	fmt.Println("--------------- SQF PROOF ----------------")
	// Prover
	priv, pub := GenerateNiceKeyPair(1024)
	fmt.Println("gcd:", new(big.Int).GCD(nil, nil, priv.N, priv.Lam))
	y := SQFProof(priv.Lam, priv.N, false)

	// Verifier
	// Fiat-Shamir
	x_bytes := sha256.Sum256(pub.N.Bytes())
        x := new(big.Int).SetBytes(x_bytes[:])
	yn := new(big.Int).Exp(y, priv.N, priv.N)
	fmt.Println("yn:", yn)
	fmt.Println("x:", x)
	fmt.Println("Passes honest proof?: ", yn.Cmp(x) == 0)
}

func TestBadProofSQF(t *testing.T) {
	fmt.Println("---------------- SQF BAD PROOF ----------------")
	priv, pub, ps, qs := GenerateAttackKey(1024)

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
	//fmt.Println(lambda, priv.N)
	fmt.Println("pt = gcd(N, lambda) ? :", pt.Cmp(new(big.Int).GCD(nil, nil, priv.N, lambda)))
	y := SQFProof(lambda, priv.N, true) // Not coprime, cant compute well

	// Fiat-Shamir
        x_bytes := sha256.Sum256(pub.N.Bytes())
        x := new(big.Int).SetBytes(x_bytes[:])
	yn := new(big.Int).Exp(y, pub.N, pub.N)
	fmt.Println("yn:", yn)
	fmt.Println("x:", x)
	fmt.Println("Passes bad proof?: ", yn.Cmp(x) == 0)
}

func TestProofPPP(t *testing.T) {
	sec := 3

	fmt.Println("---------------- PPP PROOF ----------------")
	priv, pub := GenerateNiceKeyPair(256)

	sqs, sq2s, is, ok := PPPProof(priv.N, priv.P, priv.Q, sec, false)
	for _, sq2 := range(sq2s) {
		sq2.Mod(sq2, priv.N)
	}
	fmt.Println("Proof exists:", ok, len(sqs) == len(sq2s))
	if !ok {
		return
	}

	h := new(big.Int).Set(pub.N)
	for j, _ := range(sqs) {
		fmt.Println("iter:", j)
		fmt.Println("i:", is[j])
		v := new(big.Int).Exp(sqs[j], big.NewInt(2), pub.N)
		fmt.Println("v:", v)
		fmt.Println("sq2s:", sq2s[j])
		// Verifier should check that sqs2 is x, -x, 2x, or -2x
		// Fiat-Shamir
        	x_bytes := sha256.Sum256(h.Bytes())
        	x := new(big.Int).SetBytes(x_bytes[:])
		if v.Cmp(new(big.Int).Mod(x, pub.N)) == 0 {
			fmt.Println("Passes verification x")
		} else if v.Cmp(new(big.Int).Mod(new(big.Int).Neg(x), pub.N)) == 0 {
			fmt.Println("Passes verification -x")
		} else if v.Cmp(new(big.Int).Mod(new(big.Int).Add(x, x), pub.N)) == 0 {
			fmt.Println("Passes verification 2x")
		} else if v.Cmp(new(big.Int).Mod(new(big.Int).Neg(new(big.Int).Add(x, x)), pub.N)) == 0 {
			fmt.Println("Passes verification -2x")
		} else {
			fmt.Println("Wrong square")
		}

/*
		if sq2s[j].Sub(sq2s[j], v).Mod(sq2s[j], pub.N).Cmp(Zero) != 0 {
			fmt.Println("Wrong square")
		} else {
			fmt.Println("Passes verification")
		}
*/
		h.Add(h, One)
	}

	fmt.Println("P:", priv.P)
	fmt.Println("Q:", priv.Q)
	fmt.Println("P mod 8: ", new(big.Int).Mod(priv.P, Eight))
	fmt.Println("Q mod 8: ", new(big.Int).Mod(priv.Q, Eight))
	fmt.Println("P-Q mod 8: ", new(big.Int).Mod(new(big.Int).Add(priv.P, new(big.Int).Neg(priv.Q)), Eight))
}


func TestBadProofPPP(t *testing.T) {
        sec := 5

        fmt.Println("---------------- PPP BAD PROOF ----------------")
        priv, pub := GenerateNiceKeyPair(256)

        sqs, sq2s, is, ok := PPPProof(pub.N, priv.P, priv.Q, sec, true)
        fmt.Println("Proof exists:", ok, len(sqs) == len(sq2s))
        if !ok {
                return
        }

        h := new(big.Int).Set(pub.N)
        for j, _ := range(sqs) {
                fmt.Println("iter:", j)
                fmt.Println("i:", is[j])
                v := new(big.Int).Exp(sqs[j], big.NewInt(2), pub.N)
                fmt.Println("sq:", sqs[j])
		fmt.Println("gcd sq, N:", new(big.Int).GCD(nil, nil, sqs[j], pub.N))
		fmt.Println("v:", v)
                fmt.Println("sq2s:", sq2s[j])
                // Verifier should check that sqs2 is x, -x, 2x, or -2x
                // Fiat-Shamir
                x_bytes := sha256.Sum256(h.Bytes())
                x := new(big.Int).SetBytes(x_bytes[:])
                if v.Cmp(new(big.Int).Mod(x, pub.N)) == 0 {
                        fmt.Println("Passes verification x")
                } else if v.Cmp(new(big.Int).Mod(new(big.Int).Neg(x), pub.N)) == 0 {
                        fmt.Println("Passes verification -x")
                } else if v.Cmp(new(big.Int).Mod(new(big.Int).Add(x, x), pub.N)) == 0 {
                        fmt.Println("Passes verification 2x")
                } else if v.Cmp(new(big.Int).Mod(new(big.Int).Neg(new(big.Int).Add(x, x)), pub.N)) == 0 {
                        fmt.Println("Passes verification -2x")
                } else {
                        fmt.Println("Wrong square")
                }
                h.Add(h, One)
        }
}
