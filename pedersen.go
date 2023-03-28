
package main

import (
	"crypto/sha256"
	"math/big"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

// Public parameters
var secp256r1 = elliptic.P256()
var Gx = secp256r1.Params().Gx
var Gy = secp256r1.Params().Gy
var G = ECPoint{X: Gx, Y: Gy}
var A_string = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"
var B_string = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
var H = ECPoint{}



// Pick second generator based on a public, agreed-upon method (hash G for example)
func Setup(){
	A, err := new(big.Int).SetString(A_string, 16)
	fmt.Println(err)
	B, err := new(big.Int).SetString(B_string, 16)
	fmt.Println("err, B:", err, B)
	fmt.Println("paramB:", secp256r1.Params().P)

	var Hx, Hy *big.Int
	for {
		Hx_hash := sha256.Sum256(Gx.Bytes()) // May need to do mod P
		Hx := new(big.Int).SetBytes(Hx_hash[:])
		//Hy := curve(Hx)
		x3 := new(big.Int).Exp(Hx, big.NewInt(3), secp256r1.Params().P)
		Ax := new(big.Int).Mul(A, Hx)
		x3plusAx := new(big.Int).Add(x3, Ax)
		y2 := new(big.Int).Add(x3plusAx, B)
		Hy := new(big.Int).ModSqrt(y2, secp256r1.Params().P)

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

