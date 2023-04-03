package main

import (
	"math/big"
//	"bytes"
//	"encoding/binary"
	"testing"
	"fmt"
)


func TestPedersen(t *testing.T) {
	fmt.Println("-----------------")
	Setup(Zero)

        v := big.NewInt(33)
        r, C := Commit(v.Bytes())
        fmt.Println("Verify?: ", VerifyCommitment(v.Bytes(), r, C))
}

func TestSumPedersen(t *testing.T) {
	fmt.Println("-----------------")
        Setup(Zero)

        v1 := big.NewInt(33)
        r1, C1 := Commit(v1.Bytes())
        fmt.Println("Verify v1?: ", VerifyCommitment(v1.Bytes(), r1, C1))

	v2 := big.NewInt(101)
	r2, C2 := Commit(v2.Bytes())
        fmt.Println("Verify v2?: ", VerifyCommitment(v2.Bytes(), r2, C2))

	v3 := new(big.Int).Add(v1, v2)
        r1_big := new(big.Int).SetBytes(r1)
	r2_big := new(big.Int).SetBytes(r2)
	r3 := new(big.Int).Add(r1_big, r2_big).Bytes()
	C3X, C3Y := secp256r1.Add(C1.X, C1.Y, C2.X, C2.Y)
        C3 := &ECPoint{X: C3X, Y: C3Y}
	fmt.Println("Verify v3?: ", VerifyCommitment(v3.Bytes(), r3, C3))

}


// Since H = kG
// dishonest prover can set v to fake_v
// and r to fake_r = r + k * (v - fake_v)
// and still pass the test
func TestEvilPedersen(t *testing.T) {
	fmt.Println("-----------------")
        Setup(big.NewInt(13))

  	v := big.NewInt(12100)
        r, C := Commit(v.Bytes())
        fmt.Println("Verify?: ", VerifyCommitment(v.Bytes(), r, C))

	// Craft fake_v
	fake_v := big.NewInt(3390)

	r_big := new(big.Int).SetBytes(r)

	difv := new(big.Int).Sub(v, fake_v)
	kdifv := new(big.Int).Mul(K, difv)
	fake_r := new(big.Int).Add(r_big, kdifv)
	fake_r.Mod(fake_r, secp256r1.Params().N)

	fmt.Println("fake_r_int mod N bigint:", fake_r)
	fmt.Println("fake_r_bigint_bytes:", fake_r.Bytes())

        fmt.Println("EvilVerify?: ", VerifyCommitment(fake_v.Bytes(), fake_r.Bytes(), C))
}

