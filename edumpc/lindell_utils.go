package edumpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
)

var CurveLindell = elliptic.P256()

func KeyGenLindell(x_a, x_b *big.Int, paillier_bits int) (*PaillierPriv, *PaillierPub, *big.Int, *ecdsa.PublicKey) {
	// Paillier key pair, belongs to B
	priv, pub := GenerateNiceKeyPair(paillier_bits)

	// Encrypt x_b with paillier, send to A
	x_b_enc := pub.Encrypt(x_b)

	// Public shared key
	X_a_x, X_a_y := CurveLindell.ScalarBaseMult(x_a.Bytes())
	X_b_x, X_b_y := CurveLindell.ScalarBaseMult(x_b.Bytes())
	X_x, X_y := CurveLindell.Add(X_a_x, X_a_y, X_b_x, X_b_y)
	X := &ecdsa.PublicKey{CurveLindell, X_x, X_y}

	return priv, pub, x_b_enc, X
}

func SignLindell(m string, pub *PaillierPub, priv *PaillierPriv, x_a, x_b, x_b_enc, k_a, k_b *big.Int, attack bool, l, y_b *big.Int) (*big.Int, *big.Int) {
	m_hash := sha256.Sum256([]byte(m))
	m_hash_bigint := hashToInt(m_hash[:], CurveLindell)

	// Public shared nonce
	r, _ := MulShareLindell(k_a, k_b)
	//fmt.Println("r:", r)

	// Protocol 3.3 Step 3 (Party A) or Attack 3.5
	D := new(big.Int)
	if attack {
		D = SignLindellAdversaryPartyA(x_a, k_a, r, m_hash_bigint, x_b_enc, l, y_b, pub, priv, k_b)
	} else {
		D = SignLindellPartyA(x_a, k_a, r, m_hash_bigint, x_b_enc, pub)
	}

	// Protocol 3.3 Step 4 (Party B)
	s := SignLindellPartyB(k_b, D, priv)

	return r, s
}

func SignLindellPartyA(x_a, k_a, r, m_hash_bigint, x_b_enc *big.Int, pub *PaillierPub) *big.Int {
	k_a_inv := new(big.Int).ModInverse(k_a, CurveLindell.Params().N)

	// Enc( k_a^-1 * (hash + r * x_a) )
	res1 := new(big.Int).Mul(r, x_a)
	res1.Add(res1, m_hash_bigint)
	res1.Mul(res1, k_a_inv)
	res1.Mod(res1, CurveLindell.Params().N)
	res1 = pub.Encrypt(res1)

	// x_b_enc ^ (r * k_a^-1)
	// Should equal Enc( (r * k_a^-1) * x_b )
	res2 := new(big.Int).Mul(r, k_a_inv)
	res2.Mod(res2, CurveLindell.Params().N)
	res2.Exp(x_b_enc, res2, pub.N2)
	//fmt.Println("res2:", res2)

	res1.Mul(res1, res2)
	res1.Mod(res1, pub.N2) // res1 (D) is sent to party B
	// fmt.Println("res1:", res1)
	return res1
}

func SignLindellPartyB(k_b, D *big.Int, priv *PaillierPriv) *big.Int {
	// k_b^-1 * Dec( D )
	k_b_inv := new(big.Int).ModInverse(k_b, CurveLindell.Params().N)
	res1_dec := priv.Decrypt(D)
	s := new(big.Int).Mul(k_b_inv, res1_dec)
	s.Mod(s, CurveLindell.Params().N)
	return s
}

func SignLindellAdversaryPartyA(x_a, k_a, r, m_hash_bigint, x_b_enc, l, y_b *big.Int, pub *PaillierPub, priv *PaillierPriv, k_b *big.Int) *big.Int {
	// Attack 3.5 Step 1
	k_a_inv := new(big.Int).ModInverse(k_a, CurveLindell.Params().N)
	k_a_inv_N := new(big.Int).ModInverse(k_a, pub.N)
	epsilon := new(big.Int).Sub(k_a_inv, k_a_inv_N)

	r_prime := new(big.Int).Set(r)
	if r_prime.Bit(0) == 0 {
		r_prime.Add(r, CurveLindell.Params().N)
	}
	//fmt.Println("r_prime:", r_prime)

	// Attack 3.5 Step 2
	// Enc( k_a^-1 * (hash + r * x_a) + offset )
	res1 := new(big.Int).Mul(r, x_a)
	res1.Add(res1, m_hash_bigint)
	res1.Mul(k_a_inv, res1)
	res1.Mod(res1, CurveLindell.Params().N)

	offset := new(big.Int).Mul(y_b, r_prime)
	offset.Mul(offset, epsilon)
	//fmt.Println("offset:", offset)

	res1.Add(res1, offset)
	res1 = pub.Encrypt(res1)

	// x_b_enc ^ (r_prime * (k_a^-1 mod N))
	res2 := new(big.Int).Mul(r_prime, k_a_inv_N)
	//res2.Mod(res2, CurveLindell.Params().N) ?
	res2.Exp(x_b_enc, res2, pub.N2) //mod N2?
	//fmt.Println("res2:", res2)

	res1.Mul(res1, res2)
	res1.Mod(res1, pub.N2) // res1 (D) is sent to party B
	//fmt.Println("res1:", res1)

	return res1
}

func MulShareLindell(a, b *big.Int) (*big.Int, *big.Int) {
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
