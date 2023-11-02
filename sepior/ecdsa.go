//go:build sepior
// +build sepior

package sepior

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/san-lab/EduMPC/edumpc"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

func GenerateKey() {

	// Configure your TSM here

	// Create ECDSA client from credentials

	ecdsaClient := tsm.NewECDSAClient(tsmC) // ECDSA with secp256k1 curve

	// Generate ECDSA key
	//keyID := "bki6yrPuOEcLxi1uZ5Qg9n9W56bK"

	keyID, err := ecdsaClient.Keygen("secp256k1")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated key: ID=%s\n", keyID)

	// Get the public key as a DER encoding

	derPubKey, err := ecdsaClient.PublicKey(keyID, nil)
	if err != nil {
		log.Fatal(err)
	}

	// We can now sign with the created key

	message := []byte(`Hello World`)
	hash := sha256.Sum256(message)
	derSignature, _, err := ecdsaClient.Sign(keyID, nil, hash[:])
	if err != nil {
		log.Fatal(err)
	}

	// Verify the signature relative to the signed message and the public key

	err = tsm.ECDSAVerify(derPubKey, hash[:], derSignature)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Signature: %s\n", hex.EncodeToString(derSignature))

}

func ecdsaui(n *edumpc.MPCNode) {
	InitNewSepSessionUI(n)

}
