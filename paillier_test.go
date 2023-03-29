package main
import (
	"testing"
	"fmt"
	"math/big"
)

func TestProof(t *testing.T) {
	priv, _ := GenerateNiceKeyPair(1024)
	x := big.NewInt(33)
	y := SQFProof(priv.Lam, priv.N, x)
	yn := new(big.Int).Exp(y, priv.N, priv.N)
	fmt.Println("yn:", yn)
}

func TestBadProof(t *testing.T) {
        priv, _, ps, qs := GenerateAttackKey(1024)
        x := big.NewInt(33)
	lambda := big.NewInt(1)
	for _, p := range ps {
		pm1 := new(big.Int).Sub(p, One)
		lambda.Mul(lambda, pm1)
	}
	for _, q := range qs {
                qm1 := new(big.Int).Sub(q, One)
                lambda.Mul(lambda, qm1)
        }
	fmt.Println(lambda, priv.N, x)
        y := SQFProof(lambda, priv.N, x)
        yn := new(big.Int).Exp(y, priv.N, priv.N)
        fmt.Println("yn2:", yn)
}
