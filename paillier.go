package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var One = big.NewInt(1)

// Returns a key pair. The arguments p and q are *assumed* to be primes of equal length
// (but we may want to abuse this assumption later to see some exploits).
func GenerateKeyPair(p, q *big.Int) (*PaillierPriv, *PaillierPub) {
	Priv := new(PaillierPriv)
	Priv.N = new(big.Int).Mul(p, q)
	Pm1 := new(big.Int).Sub(p, One)
	Qm1 := new(big.Int).Sub(q, One)
	Priv.N2 = new(big.Int).Mul(Priv.N, Priv.N)
	Priv.Lam = new(big.Int).Mul(Pm1, Qm1)
	Priv.Miu = new(big.Int).ModInverse(Priv.Lam, Priv.N)
	Pub := &PaillierPub{new(big.Int).Set(Priv.N), new(big.Int).Set(Priv.N2)}
	Priv.Pub = Pub

	return Priv, Pub

}

func GenerateNiceKeyPair(bits int) (*PaillierPriv, *PaillierPub) {
	P, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		fmt.Println(err)
		return nil, nil
	}
	Q := big.NewInt(0).Set(P)
	for P.Cmp(Q) == 0 {
		Q, err = rand.Prime(rand.Reader, bits)
		if err != nil {
			fmt.Println(err)
			return nil, nil
		}
	}
	return GenerateKeyPair(P, Q)
}

type PaillierPub struct {
	N  *big.Int
	N2 *big.Int
}

type PaillierPriv struct {
	Lam *big.Int
	Miu *big.Int
	N   *big.Int
	N2  *big.Int
	Pub *PaillierPub
}

func (pub *PaillierPub) EncryptWithR(m, r *big.Int) *big.Int {
	G := new(big.Int).Add(pub.N, One)
	enc := new(big.Int).Exp(G, m, pub.N2)
	rn := new(big.Int).Exp(r, pub.N, pub.N2)
	enc.Mul(enc, rn)
	enc.Mod(enc, pub.N2)
	return enc

}

func (pub *PaillierPub) Encrypt(m *big.Int) *big.Int {
	r, err := rand.Int(rand.Reader, pub.N)
	if err != nil {
		fmt.Println(err)
	}
	for new(big.Int).GCD(nil, nil, r, pub.N).Cmp(One) != 0 {
		r, err = rand.Int(rand.Reader, pub.N)
		if err != nil {
			fmt.Println(err)
		}
	}
	return pub.EncryptWithR(m, r)

}

func (priv *PaillierPriv) Decrytpt(ct *big.Int) *big.Int {
	m := new(big.Int)
	c := new(big.Int)
	c.Exp(ct, priv.Lam, priv.N2)
	m.Mul(L(c, priv.N), priv.Miu)
	m.Mod(m, priv.N)
	return m
}

func L(x, n *big.Int) *big.Int {
	y := new(big.Int).Set(x)
	y.Sub(y, One)
	y.Div(y, n)
	return y

}

func (pub *PaillierPub) EqModN(a, b *big.Int) bool {
	ac := new(big.Int).Mod(a, pub.N)
	bc := new(big.Int).Mod(b, pub.N)
	return (ac.Cmp(bc) == 0)

}

func GenerateAttackKey(bits int) (*PaillierPriv, *PaillierPub, []*big.Int, []*big.Int) {
	Pt := big.NewInt(1)
	Qt := big.NewInt(1)
	Ps := []*big.Int{}
	Qs := []*big.Int{}
	currbits := 0
	for currbits < bits*2 {
		var P, Q *big.Int

		Q = big.NewInt(4)
		for !Q.ProbablyPrime(0) {
			P, _ = rand.Prime(rand.Reader, 16)
			used := false
			for i := range Ps {
				if Ps[i].Cmp(P) == 0 {
					used = true
					break
				}
			}
			if used {
				continue
			}
			Q = new(big.Int).Add(P, P)
			Q.Add(Q, One)
		}
		Ps = append(Ps, P)
		Qs = append(Qs, Q)
		currbits += P.BitLen()
		currbits += Q.BitLen()
		Pt.Mul(Pt, P)
		Qt.Mul(Qt, Q)
	}
	Priv, Pub := GenerateKeyPair(Pt, Qt)
	return Priv, Pub, Ps, Qs

}

func FireblocksAttack(aV *big.Int, V *big.Int, Ps, Qs []*big.Int) ([]*big.Int, []*big.Int, *big.Int) {
	rs := []*big.Int{}
	xs := []*big.Int{}
	for i := range Ps {
		P1 := new(big.Int).Add(Ps[i], One)
		cmq := new(big.Int).Mod(V, Qs[i])
		r := new(big.Int).Exp(cmq, P1, Qs[i])
		rs = append(rs, r)
		//brute force attack
		for x := big.NewInt(0); x.Cmp(Ps[i]) < 0; x.Add(x, One) {
			if (new(big.Int).Exp(aV, x, Qs[i]).Cmp(r) == 0) {
				xs = append(xs, x)
				break
			}
		}
	}
	fmt.Println(rs)
	fmt.Println(xs)
	x, _ := crt(xs, Ps)
	return rs, xs, x
}

func crt(a, n []*big.Int) (*big.Int, error) {
    p := new(big.Int).Set(n[0])
    for _, n1 := range n[1:] {
        p.Mul(p, n1)
    }
    var x, q, s, z big.Int
    for i, n1 := range n {
        q.Div(p, n1)
        z.GCD(nil, &s, n1, &q)
        if z.Cmp(One) != 0 {
            return nil, fmt.Errorf("%d not coprime", n1)
        }
        x.Add(&x, s.Mul(a[i], s.Mul(&s, &q)))
    }
    return x.Mod(&x, p), nil
}
