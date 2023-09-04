package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

var CurveLindell = elliptic.P256()
var paillier_bits = 1024

func KeyGenLindell() (*PaillierPriv, *PaillierPub, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int) {
	// Paillier key pair, belongs to B
	priv, pub := GenerateNiceKeyPair(paillier_bits)
	//fmt.Println("priv:", priv)
	//fmt.Println("pub:", pub)

	// Gen x_a, x_b
	x_a := big.NewInt(33)
	x_b := big.NewInt(98)
	fmt.Println("x_a, x_b:", x_a, x_b)

	// Encrypt x_b with paillier, send to A
	x_b_enc := pub.Encrypt(x_b)
	//fmt.Println("x_b_enc:", x_b_enc)

	//x_b_dec := priv.Decrypt(x_b_enc)
	//fmt.Println(x_b_dec)

	X_a_x, X_a_y := CurveLindell.ScalarBaseMult(x_a.Bytes())
	X_b_x, X_b_y := CurveLindell.ScalarBaseMult(x_b.Bytes())
	X_x, X_y := CurveLindell.Add(X_a_x, X_a_y, X_b_x, X_b_y)
	fmt.Println("X_x, X_y:", X_x, X_y)

	//x_ab := new(big.Int).Add(x_a, x_b)
	//X_x2, X_y2 := CurveLindell.ScalarBaseMult(x_ab.Bytes())
	//fmt.Println(X_x2, X_y2)

	return priv, pub, x_a, x_b, x_b_enc, X_x, X_y
}

func SignLindell(m string, pub *PaillierPub, priv *PaillierPriv, x_a, x_b, x_b_enc, X_x, X_y *big.Int) {
	fmt.Println("-------------")
	m_hash := sha256.Sum256([]byte(m))
	m_hash_bigint_bad := new(big.Int).SetBytes(m_hash[:]) // With this message outputs the same bigint, but could be worng in general
	fmt.Println(m_hash_bigint_bad)
	m_hash_bigint := hashToInt(m_hash[:], CurveLindell)
	fmt.Println(m_hash_bigint)

	// Sample nonces
	k_a := big.NewInt(44)
	k_b := big.NewInt(87)
	R_x, _ := MulShare(k_a, k_b)
	fmt.Println("R_x:", R_x)

	// Protocol 3.3 Step 3 (Party A)
	k_a_inv := new(big.Int).ModInverse(k_a, CurveLindell.Params().N)

	//Enc( k_a^-1 * (hash + R_x * x_a) )
	res1 := new(big.Int).Mul(k_a_inv, m_hash_bigint.Add(m_hash_bigint, R_x.Mul(R_x, x_a)))
	res1.Mod(res1, CurveLindell.Params().N)
	pub.Encrypt(res1)

	// x_b_enc ^ (R_x * k_a^-1)
	res2 := new(big.Int).Mul(R_x, k_a_inv)
	res2.Mod(res2, CurveLindell.Params().N)
	res2.Exp(x_b_enc, res2, pub.N2) //mod N2?
	fmt.Println("res2:", res2)
	// Enc( (R_x * k_a^-1) * x_b )
	res2_dec := priv.Decrypt(res2)
	fmt.Println("res2_dec:", res2_dec)
	res2_dec_real := new(big.Int).Mul(R_x, k_a_inv)
	res2_dec_real.Mod(res2_dec_real, CurveLindell.Params().N)
	res2_dec_real.Mul(res2_dec_real, x_b)
	res2_dec_real.Mod(res2_dec_real, pub.N2)
	fmt.Println("res2_dec_real:", res2_dec_real)
	fmt.Println("enc:", pub.Encrypt(res2_dec_real))

	res1.Mul(res1, res2)
	res1.Mod(res1, pub.N2) // res1 (D) is sent to party B
	fmt.Println("res1:", res1)

	// Party B
	k_b_inv := new(big.Int).ModInverse(k_b, CurveLindell.Params().N)
	res1_dec := priv.Decrypt(res1)
	s := new(big.Int).Mul(k_b_inv, res1_dec)
	s.Mod(s, CurveLindell.Params().N)
	fmt.Println("s:", s)

	X := &ecdsa.PublicKey{CurveLindell, X_x, X_y}
	fmt.Println("verify?", ecdsa.Verify(X, m_hash[:], R_x, s))

	// What the "s" really should be
	fmt.Println("-------------")
	k_inv1 := new(big.Int).Mul(k_b_inv, k_a_inv)
	k_inv1.Mod(k_inv1, CurveLindell.Params().N)
	fmt.Println("k_inv_1:", k_inv1)
	k_inv2 := new(big.Int).ModInverse(new(big.Int).Mul(k_a, k_b), CurveLindell.Params().N)
	fmt.Println("k_inv_2:", k_inv2)
	k_inv2.Mul(k_inv2, new(big.Int).Mul(k_a, k_b))
	k_inv2.Mod(k_inv2, CurveLindell.Params().N)
	fmt.Println("k_inv_2 * k % N:", k_inv2)

	privkey := new(big.Int).Add(x_a, x_b)
	fmt.Println("privkey:", privkey)
	//s = k^-1 * (hash + R_x * privkey)
	s_real_aux := new(big.Int).Add(m_hash_bigint, new(big.Int).Mul(R_x, privkey))
	s_real := new(big.Int).Mul(k_inv1, s_real_aux)
	s_real.Mod(s_real, CurveLindell.Params().N)
	fmt.Println("s_real:", s_real)
	fmt.Println(R_x.Sign(), s_real.Sign())
	fmt.Println("verify2?", ecdsa.Verify(X, m_hash[:], R_x, s_real))
}

func RegularECDSA(m string, x_a, x_b, X_x, X_y *big.Int) {
	fmt.Println("-------------")
	m_hash := sha256.Sum256([]byte(m))

	pub_ecdsa := &ecdsa.PublicKey{CurveLindell, X_x, X_y}
	x := new(big.Int).Add(x_a, x_b)
	priv_ecdsa := &ecdsa.PrivateKey{*pub_ecdsa, x}

	r, s, err := ecdsa.Sign(rand.Reader, priv_ecdsa, m_hash[:])
	fmt.Println("err, r, s:", err, r, s)
	fmt.Println("regular verify?", ecdsa.Verify(pub_ecdsa, m_hash[:], r, s))
}

func MulShare(a, b *big.Int) (*big.Int, *big.Int) {
	ab := new(big.Int).Mul(a, b)
	ab.Mod(ab, CurveLindell.Params().N)
	R_x, R_y := CurveLindell.ScalarBaseMult(ab.Bytes())
	R_x.Mod(R_x, CurveLindell.Params().N)
	R_y.Mod(R_y, CurveLindell.Params().N)
	return R_x, R_y
}

// golang hashToInt used in ecdsa
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}
