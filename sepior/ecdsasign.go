//go:build sepior
// +build sepior

package sepior

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/manifoldco/promptui"
	"github.com/san-lab/EduMPC/edumpc"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

const selectkey = "Select key"
const setmessage = "Set message to sign"
const triggersign = "Initiate signing"

var curkey *tsm.Key
var curkeyid string
var messagetosign string

func TriggerSigningPrompt(mpcn *edumpc.MPCNode) {
	for {
		label := fmt.Sprintf("ECDSASignig")
		key_l := fmt.Sprintf("%s (%s)", selectkey, curkeyid)
		msg_l := fmt.Sprintf("%s (%s)", setmessage, messagetosign)
		pr := promptui.Select{Label: label, Items: []string{key_l, msg_l, triggersign, up}}
		_, resp, _ := pr.Run()
		switch resp {
		case up:
			return
		case key_l:
			curkeyid, curkey = SelectKey(ecKey)
		case msg_l:
			pr := promptui.Prompt{}
			pr.Label = fmt.Sprintf("Message to sign: %s", messagetosign)
			pr.Default = messagetosign
			messagetosign, _ = pr.Run()
		case triggersign:
			sig, err := TriggerSigning(messagetosign)
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Println("Signature:", hex.EncodeToString(sig))
			}
		default:
			fmt.Println("Not implemented")
		}
	}
}

func TriggerSigning(messagetosign string) (signature []byte, err error) {
	if len(messagetosign) == 0 {
		err = fmt.Errorf("Message not set")
		return
	}
	mhash := sha256.Sum256([]byte(messagetosign))
	if curkey == nil {
		err = fmt.Errorf("Key not selected")
		return
	}
	ecC := tsm.NewECDSAClient(tsmC)
	//sepsesid := ecC.GenerateSessionID()
	signature, _, err = ecC.Sign(curkeyid, nil, mhash[:])
	if err != nil {
		return
	}

	derPubKey, err := ecC.PublicKey(curkeyid, nil)
	if err != nil {
		return
	}

	err = tsm.ECDSAVerify(derPubKey, mhash[:], signature)
	return

}
