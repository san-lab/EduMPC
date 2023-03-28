package main

import (
	"math/big"
	"crypto/elliptic"
	"crypto/rand"
//	"fmt"
)

//Public parameters
var secp256r1 = elliptic.P256()
var Gx = secp256r1.Params().Gx
var Gy = secp256r1.Params().Gy
var G = ECPoint{X: Gx, Y: Gy}
var H = ECPoint{}

// Pick second generator based on a public, agreed-upon method (hash G for example)
func Setup(){
	var Hx, Hy *big.Int
	for {
		//Hx := sha256.Sum256(Gx) // May need to do mod P
		//Hy := curve(Hx)

		//Testing..
		Hx, Hy = secp256r1.ScalarMult(G.X, G.Y, []byte{2})

		if secp256r1.IsOnCurve(Hx, Hy) {
			break
		}
	}
	H = ECPoint{X: Hx, Y: Hy}
}

// Commitment C = rG + vH
func Commit(v []byte) ([]byte, *ECPoint) {
	r := make([]byte, 10) // Size should be log2(order of the underlying field) ??
	rand.Read(r)
	r = []byte{0, 0, 0, 0, 0, 0, 0, 123}

	rGx, rGy := secp256r1.ScalarMult(G.X, G.Y, r)
	vHx, vHy := secp256r1.ScalarMult(H.X, H.Y, v)
	Cx, Cy := secp256r1.Add(rGx, rGy, vHx, vHy)
	C := ECPoint{X: Cx, Y: Cy}
	return r, &C
}

// Send r, v
func Reveal() {
	// return r, v
}

// Check whether  C = rG + vH
func VerifyCommitment(v []byte, r []byte, C *ECPoint) bool {
	rGx, rGy := secp256r1.ScalarMult(G.X, G.Y, r)
        vHx, vHy := secp256r1.ScalarMult(H.X, H.Y, v)
        Cx, Cy := secp256r1.Add(rGx, rGy, vHx, vHy)
	if Cx.Cmp(C.X) == 0 && Cy.Cmp(C.Y) == 0 {
		return true
	}
        return false
}



