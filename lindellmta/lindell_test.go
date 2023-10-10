package lindellmta

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/san-lab/EduMPC/somecrypto"
)

func TestHonestExecution(t *testing.T) {
	paillier_bits := 1024
	m := "test"
	m_hash := sha256.Sum256([]byte(m))

	x_a := big.NewInt(97)
	x_b := big.NewInt(33)
	k_a := big.NewInt(882)
	k_b := big.NewInt(220)

	attack := false
	l := big.NewInt(0)
	y_b := big.NewInt(0)

	priv, pub, x_b_enc, edcsaPubKey := KeyGenLindell(x_a, x_b, paillier_bits)
	r, s := SignLindell(m, pub, priv, x_a, x_b, x_b_enc, k_a, k_b, attack, l, y_b)
	fmt.Println("Verifies?", ecdsa.Verify(edcsaPubKey, m_hash[:], r, s))
}

func TestFullCrack(t *testing.T) {
	paillier_bits := 1024
	m := "test"
	m_hash := sha256.Sum256([]byte(m))

	attack := true

	x_a := big.NewInt(33)
	x_b, _ := rand.Int(rand.Reader, big.NewInt(1000))
	fmt.Println("x_b:", x_b)
	k_b, _ := rand.Int(rand.Reader, big.NewInt(100000000))

	priv, pub, x_b_enc, ecdsaPubKey := KeyGenLindell(x_a, x_b, paillier_bits)

	l := big.NewInt(1)
	y_b := big.NewInt(0)
	bitstring := ""
	for i := 0; i < x_b.BitLen(); i++ {
		k_a := new(big.Int).Exp(big.NewInt(2), l, nil)

		r, s := SignLindell(m, pub, priv, x_a, x_b, x_b_enc, k_a, k_b, attack, l, y_b)
		verifies := ecdsa.Verify(ecdsaPubKey, m_hash[:], r, s)

		if !verifies {
			bitstring = "1" + bitstring
			fmt.Println("1")
			inc_y_b := new(big.Int).Div(k_a, big.NewInt(2))
			y_b.Add(y_b, inc_y_b)
		} else {
			bitstring = "0" + bitstring
			fmt.Println("0")
		}
		l.Add(l, big.NewInt(1))
	}
	fmt.Println("Bits:", bitstring)
	fmt.Println("Share of b:", y_b)

}

func Test1BitCrack(t *testing.T) {
	paillier_bits := 1024
	m := "test"
	m_hash := sha256.Sum256([]byte(m))

	attack := true

	x_a := big.NewInt(33)
	x_b, _ := rand.Int(rand.Reader, big.NewInt(100000000))
	fmt.Println("x_b:", x_b)
	k_b, _ := rand.Int(rand.Reader, big.NewInt(100000000))

	priv, pub, x_b_enc, ecdsaPubKey := KeyGenLindell(x_a, x_b, paillier_bits)

	l := big.NewInt(1)
	y_b := big.NewInt(0)
	k_a := new(big.Int).Exp(big.NewInt(2), l, nil) // Nonce A must be 2^l

	r, s := SignLindell(m, pub, priv, x_a, x_b, x_b_enc, k_a, k_b, attack, l, y_b)
	verifies := ecdsa.Verify(ecdsaPubKey, m_hash[:], r, s)
	fmt.Println("Verifies?", verifies)
	if !verifies {
		fmt.Println("Secret share is odd")
	} else {
		fmt.Println("Secret share is even")
	}
}

func TestRegularECDSA(t *testing.T) {
	m := "test"
	m_hash := sha256.Sum256([]byte(m))

	r_string := "5337407977023252675875353662396634111516345258063351381573848408544500368789"
	r, _ := new(big.Int).SetString(r_string, 10)

	s_string := "55943867479559448264327755242616004879254043100908540146074908153747607961016"
	s, _ := new(big.Int).SetString(s_string, 10)

	pubX_string := "84718483466365298059777001458829903729449000391414678176588410096217186804315"
	pubY_string := "16861405308691180008685345224945504339827926551724803149071209790867939065707"
	pubX, _ := new(big.Int).SetString(pubX_string, 10)
	pubY, _ := new(big.Int).SetString(pubY_string, 10)
	ecdsaPubKey := &ecdsa.PublicKey{CurveLindell, pubX, pubY}

	verifies := ecdsa.Verify(ecdsaPubKey, m_hash[:], r, s)
	fmt.Println("Verifies?", verifies)

	fmt.Println("------------------")

	privKey := new(big.Int).Add(big.NewInt(33), big.NewInt(97))
	//ecdsaPrivKey := &ecdsa.PrivateKey{ecdsaPubKey, privKey}
	X, Y := CurveLindell.ScalarBaseMult(privKey.Bytes())
	fmt.Println("share x right?", X.Cmp(pubX))
	fmt.Println("share y right?", Y.Cmp(pubY))

	fmt.Println("------------------")

	pubNonceX_string := "5337407977023252675875353662396634111516345258063351381573848408544500368789"
	pubNonceY_string := "80118119287206223902658705667669470074902059603207037094839574469837893270779"
	pubNonceX, _ := new(big.Int).SetString(pubNonceX_string, 10)
	pubNonceY, _ := new(big.Int).SetString(pubNonceY_string, 10)

	privNonce := new(big.Int).Mul(big.NewInt(882), big.NewInt(220))
	nonceX, nonceY := CurveLindell.ScalarBaseMult(privNonce.Bytes())
	fmt.Println("nonce x right?", nonceX.Cmp(pubNonceX))
	fmt.Println("nonce y right?", nonceY.Cmp(pubNonceY))
}

func TestHomomorphic(t *testing.T) {
	priv, pub := somecrypto.GenerateNiceKeyPair(32)
	fmt.Println("priv:", priv)
	fmt.Println("pub:", pub)

	value := big.NewInt(123)
	value_enc := pub.Encrypt(value)
	value_dec := priv.Decrypt(value_enc)
	fmt.Println(value_dec)

	value2 := big.NewInt(2)
	value2_enc := pub.Encrypt(value2)

	value3_enc := new(big.Int).Mul(value_enc, value2_enc) // Enc(a) * Enc(b) = Enc(a + b)
	value3 := priv.Decrypt(value3_enc)
	fmt.Println(value3)

	value4 := big.NewInt(3)
	value5_enc := new(big.Int).Exp(value3_enc, value4, nil) // Enc(a)^b = Enc(b * a)
	value5 := priv.Decrypt(value5_enc)
	fmt.Println(value5)
}
