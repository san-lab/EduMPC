package edumpc

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

var Zero = big.NewInt(0)
var One = big.NewInt(1)

// var Seven = big.NewInt(7)
var Eight = big.NewInt(8)

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
	Priv.P = p
	Priv.Q = q
	return Priv, Pub

}

// (P-1)(Q-1) and N should be coprimes
func PaillierConstraint(P, Q *big.Int) bool {
	N := new(big.Int).Mul(P, Q)
	L := new(big.Int).Sub(P, One)
	L.Mul(L, new(big.Int).Sub(Q, One))
	L.GCD(nil, nil, N, L)
	return L.Cmp(One) == 0
}

// P and Q such that P != 1 mod 8, Q != 1 mod 8, P != Q mod 8 and fundamental assumption of Paillier
func GenerateNiceKeyPair(bits int) (*PaillierPriv, *PaillierPub) {
	h1 := new(big.Int)
	P := big.NewInt(9)
	Q := big.NewInt(4)
	for !PaillierConstraint(P, Q) { //Verify fundamental assumption of Paillier
		var err error
		for h1.Mod(P, Eight).Cmp(One) == 0 {
			P, err = rand.Prime(rand.Reader, bits)
			if err != nil {
				fmt.Println(err)
				return nil, nil
			}
		}
		Q.Set(P)
		for h1.Mod(h1.Sub(P, Q), Eight).Cmp(big.NewInt(0)) == 0 || h1.Mod(Q, Eight).Cmp(One) == 0 {
			Q, err = rand.Prime(rand.Reader, bits)
			if err != nil {
				fmt.Println(err)
				return nil, nil
			}
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
	P   *big.Int
	Q   *big.Int
}

// Enc = (N+1)^m * r^N mod N^2
func (pub *PaillierPub) EncryptWithR(m, r *big.Int) *big.Int {
	G := new(big.Int).Add(pub.N, One)
	enc := new(big.Int).Exp(G, m, pub.N2)
	rn := new(big.Int).Exp(r, pub.N, pub.N2)
	enc.Mul(enc, rn)
	enc.Mod(enc, pub.N2)
	return enc

}

// Smaple r such that r and N are coprimes
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

func (priv *PaillierPriv) Decrypt(ct *big.Int) *big.Int {
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

// Malicious modulus N = p1 * (2p1 - 1) * p2 * (2p2 - 1) * ...
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

// Given random x, calculate x^(N^-1 mod lambda) mod N
// An attacker would just randomize the result and hope it passes the verification
// Note that N would have no inverse mod lambda if N is a malicious modulus
func SQFProof(lambda *big.Int, N *big.Int, evil bool) *big.Int {
	if evil {
		return big.NewInt(17) //TODO randomize, less than N, coprime with N
	}

	// Fiat-Shamir: challenge = hash(inputs)
	x_bytes := sha256.Sum256(N.Bytes())
	x := new(big.Int).SetBytes(x_bytes[:])

	M := new(big.Int).ModInverse(N, lambda)
	y := new(big.Int).Exp(x, M, N)
	return y
}

func PPPProof(N, P, Q *big.Int, s int, evil bool) ([]*big.Int, []*big.Int, []int, bool) {
	rps := []*big.Int{}
	xps := []*big.Int{}
	pis := []int{}
	ok := true

	if evil {
		for i := 0; i < s; i++ {
			// Smaple random int in Z_n^*
			random := new(big.Int)
			for {
				//				b := make([]byte, 1000) // size ? N.Int64() ?
				//				rand.Read(b)
				//				random.SetBytes(b)
				random, _ = rand.Int(rand.Reader, N)
				//				random.Mod(random, N)
				if new(big.Int).GCD(nil, nil, random, N).Cmp(One) == 0 {
					break
				}
			}
			rps = append(rps, random)
			// we dont care about the other params, just setting them to not re-do the tests...
			xps = append(xps, Zero)
			pis = append(pis, 0)
		}
		return rps, xps, pis, ok
	}

	h := new(big.Int).Set(N)
	for i := 0; i < s; i++ {
		// Fiat-Shamir: challenge = hash(inputs)
		x_bytes := sha256.Sum256(h.Bytes())
		x := new(big.Int).SetBytes(x_bytes[:])

		rp := new(big.Int)
		pi := 0
		//qi := 0
		xp := new(big.Int)
		//xq := new(big.Int).Set(x)
		for ; pi < 4; pi++ {
			xp = SelPPPValue(x, pi)
			rp = PQModSqrt(xp, P, Q)
			if rp != nil {
				break
			}

		}
		rps = append(rps, rp)
		xps = append(xps, xp)
		pis = append(pis, pi)
		ok = ok && (pi < 4)
		h.Add(h, One)
	}
	return rps, xps, pis, ok
}

func SelPPPValue(x *big.Int, i int) *big.Int {
	ret := new(big.Int).Set(x)
	switch i {
	case 0:
		//Nothing to do
	case 1:
		ret.Neg(ret)
	case 2:
		ret.Add(ret, ret)
	case 3:
		ret.Add(ret, ret)
		ret.Neg(ret)
	default:
		ret.SetInt64(0)
	}
	return ret
}

// n_, h1, h2 sent by  verifier. We assume theyre well-formed
func RangeProof(N, N2, n_, h1, h2 *big.Int, evil bool) (*big.Int, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int) {
	// Prover setup
	G := new(big.Int).Add(N, One)
	q := secp256r1.Params().N
	q3 := new(big.Int).Exp(q, big.NewInt(3), nil)
	qn_ := new(big.Int).Mul(q, n_)
	q3n_ := new(big.Int).Mul(q3, n_)

	m := big.NewInt(33) // < q
	if evil {
		m.Add(m, q3) // m > q^3 should fail the proof
		fmt.Println("m bigger q3?:", m.Cmp(q3))
	}
	r, _ := rand.Int(rand.Reader, N)
	for new(big.Int).GCD(nil, nil, r, N).Cmp(One) != 0 {
		r, _ = rand.Int(rand.Reader, N)
	}
	pub := &PaillierPub{N: N, N2: N2}
	c := pub.EncryptWithR(m, r)

	// Step 1
	alpha, _ := rand.Int(rand.Reader, q3)
	beta, _ := rand.Int(rand.Reader, N)
	for new(big.Int).GCD(nil, nil, beta, N).Cmp(One) != 0 {
		beta, _ = rand.Int(rand.Reader, N)
	}
	gamma, _ := rand.Int(rand.Reader, q3n_)
	rho, _ := rand.Int(rand.Reader, qn_)

	// Step 2
	z0 := new(big.Int).Exp(h1, m, n_)
	z1 := new(big.Int).Exp(h2, rho, n_)
	z := new(big.Int).Mul(z0, z1)
	z.Mod(z, n_)

	u0 := new(big.Int).Exp(G, alpha, N2)
	u1 := new(big.Int).Exp(beta, N, N2)
	u := new(big.Int).Mul(u0, u1)
	u.Mod(u, N2)

	w0 := new(big.Int).Exp(h1, alpha, n_)
	w1 := new(big.Int).Exp(h2, gamma, n_)
	w := new(big.Int).Mul(w0, w1)
	w.Mod(w, n_)

	// Fiat-Shamir e = hash(z, u, w)
	zuw := append(append(z.Bytes(), u.Bytes()...), w.Bytes()...)
	e_bytes := sha256.Sum256(zuw)
	e := new(big.Int).SetBytes(e_bytes[:])

	// Step 3
	s := new(big.Int).Exp(r, e, N)
	s.Mul(s, beta)
	s.Mod(s, N)

	s1 := new(big.Int).Mul(e, m)
	s1.Add(s1, alpha)

	s2 := new(big.Int).Mul(e, rho)
	s2.Add(s2, gamma)

	return z, u, w, s, s1, s2, c, q3
}

func PQModSqrt(x, P, Q *big.Int) *big.Int {
	r1 := new(big.Int).ModSqrt(x, P)
	r2 := new(big.Int).ModSqrt(x, Q)
	if r1 == nil {
		return r1
	}

	if r2 == nil {
		return r2
	}

	r, _ := crt([]*big.Int{r1, r2}, []*big.Int{P, Q})
	return r
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
			if new(big.Int).Exp(aV, x, Qs[i]).Cmp(r) == 0 {
				xs = append(xs, x)
				break
			}
		}
	}
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
