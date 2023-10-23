//go:build sepior
// +build sepior

package sepior

import (
	"encoding/json"
	"fmt"

	"github.com/manifoldco/promptui"
	"github.com/san-lab/EduMPC/edumpc"
	"github.com/san-lab/EduMPC/plumbing"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

type KeyGenState struct {
	Initiator     string
	ResponsesFrom []string
	KeyVerified   bool
	SepSessionID  string
	KeyID         string
	Stage         string
}

func AskToJoinKeyGeneration(ses *edumpc.Session) {

	pr := promptui.Prompt{Label: fmt.Sprintf("Join the Key Generation ceremony (ID: %s, from:  %s)? (y/n)", "x", "y"), Default: "y"}
	res, _ := pr.Run()
	if res == "y" {
		respsepmsg, err := JoinKeyGeneration(ses)
		if err != nil {
			fmt.Println(err)
			return
		}
		respmsg := new(edumpc.MPCMessage)
		respmsg.Command = "Add"
		respmsg.Protocol = ProtName
		nd, _ := plumbing.GetMPCNode()
		respmsg.SenderID = nd.GetNodeID()
		respmsg.Message = string(respsepmsg)
		ses.Interactive = false
		ses.Respond(respmsg)
		ses.Inactive = true
	}
	if res == "n" {
		ses.Inactive = true
	}

}

func TriggerKeyGeneration(mpcn *edumpc.MPCNode) {
	pr := promptui.Select{Label: "Type of the key to generate?", Items: []string{ecdsakeys, eddkeys, up}}
	_, resp, _ := pr.Run()
	switch resp {
	case ecdsakeys:
		ecC := tsm.NewECDSAClient(tsmC)
		sepsesid := ecC.GenerateSessionID()
		var keyID string
		go func() { keyID, _ = ecC.KeygenWithSessionID(sepsesid, "secp256k1") }()
		SessionID := "SEP-" + sepsesid
		ses := NewSepiorSession(mpcn, SessionID)

		sesState := ses.State.(*KeyGenState)
		sesState.Initiator = mpcn.GetNodeID()
		sesState.SepSessionID = sepsesid
		sesState.KeyID = keyID
		genmsg := new(edumpc.MPCMessage)
		genmsg.Protocol = ses.Protocol
		genmsg.Command = GenKeyCmd
		gensubmsg := new(KeyGenMsg)
		gensubmsg.KeyType = "ECDSA"
		gensubmsg.SessionID = sepsesid
		gensubmsg.KeyID = keyID
		bt, _ := json.Marshal(gensubmsg)
		genmsg.Message = string(bt)
		fmt.Println("prot", ses.Protocol)
		ses.Interactive = false
		ses.Status = "Awaiting"
		ses.Respond(genmsg)
		sesState.Stage = "Triggered"
		fmt.Println("Sent request with sessionID", genmsg.SessionID)
	default:
		fmt.Println("Not implemented")
	}
}

func JoinKeyGeneration(ses *edumpc.Session) ([]byte, error) {

	var err error
	if len(tsmC.Nodes) == 0 {
		fmt.Println("Not connected")
		return nil, fmt.Errorf("Not connected")
	}
	envelope := ses.LastMessage()
	genmsg := new(KeyGenMsg)
	json.Unmarshal([]byte(envelope.Message), genmsg)
	if len(genmsg.SessionID) > 0 {
		respmsg := new(KeyGenMsg)
		respmsg.SessionID = genmsg.SessionID
		switch genmsg.KeyType {
		case "ECDSA":
			ecC := tsm.NewECDSAClient(tsmC)
			respmsg.KeyID, err = ecC.KeygenWithSessionID(genmsg.SessionID, "secp256k1")
			if err != nil {
				fmt.Println(err)
				respmsg.Error = fmt.Sprint(err)
			}

			ses.Status = "reacted"
			ses.Interactive = false
			return json.Marshal(respmsg)

		default:
			return nil, fmt.Errorf("Key gen not implemented for:", genmsg.KeyType)
		}

	} else {
		fmt.Println("No sessionID")
		return nil, fmt.Errorf("No session id")
	}

}
