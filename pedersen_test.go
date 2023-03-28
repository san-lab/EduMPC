package main

import (
	"math/big"
	"bytes"
	"encoding/binary"
	"testing"
	"fmt"
)


func TestPedersen(t *testing.T) {
	Setup()

        v := []byte("010101value")
        r, C := Commit(v)
        fmt.Println("Verify?: ", VerifyCommitment(v, r, C))
}

func TestBytesInt(t *testing.T){
//	myInt := []byte{0, 0, 0, 0, 0, 0, 1, 245}
	myInt := []byte{149, 117, 141, 137, 115, 160, 20, 83}
	v := int64(binary.BigEndian.Uint64(myInt))
	fmt.Println("v:", v)
	e := 10769669705416315987 - 7677074368293235629
	fmt.Println(e)
	fmt.Println(secp256r1.Params().P)
}

// Since H = kG
// dishonest prover can set v to fake_v
// and r to fake_r = r + k * v - k * fake_v
// and still pass the test
func TestEvilPedersen(t *testing.T) {
        Setup()

        v := []byte("010101value")
        r, C := Commit(v)
        fmt.Println("Verify?: ", VerifyCommitment(v, r, C))

	k := int64(2)
	fake_v := []byte("evilvalue")
	fake_v_int := int64(binary.BigEndian.Uint64(fake_v))
	v_int := int64(binary.BigEndian.Uint64(v))
	r_int := int64(binary.BigEndian.Uint64(r))
	fake_r_int := r_int + k * v_int - k * fake_v_int
	fmt.Println("ints:", fake_v_int, v_int, r_int, fake_r_int)
	fake_r_bigint := big.NewInt(0).Mod(big.NewInt(fake_r_int), secp256r1.Params().P)
	fmt.Println("fake_r_int mod p:", fake_r_bigint)
	fake_r_int = fake_r_bigint.Int64()
	fmt.Println("fake_r_int:", fake_r_int)

	fake_r := new(bytes.Buffer) //make([]byte, 100)
	err := binary.Write(fake_r, binary.BigEndian, fake_r_bigint)
	fmt.Println("err:", err)
	fmt.Println("bytes.Buffer:", fake_r)
	fake_r_bytes := make([]byte, 32)
	fake_r.Read(fake_r_bytes)
	fmt.Println("[]byte:", fake_r_bytes)

        fmt.Println("EvilVerify?: ", VerifyCommitment(fake_v, fake_r_bytes, C))
}

