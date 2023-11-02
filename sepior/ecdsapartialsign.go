//go:build sepior
// +build sepior

package sepior

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/san-lab/EduMPC/edumpc"
	"github.com/san-lab/EduMPC/plumbing"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

const PartSigProtocol = edumpc.Protocol("Partial Singning Protocol")

var PartSigHandler = &edumpc.SessionHandler{nil, nil, nil, nil}

func InitNewParSigSessionUI(mpcn *edumpc.MPCNode) {
	TriggerPartialSigningPrompt(mpcn)
}

type ECDSAPartialSignState struct {
	Initiator      string
	ResponsesFrom  []string
	NodesAvailable map[string]string //mapping url to peer id
	Message        []byte
	PubKeyDer      []byte
	SignatureDER   []byte
	SepSessionID   string
	KeyID          string
	KeyType        string
	Curve          string
	Stage          string
}

type ECDSAPartialSignMessage struct {
	Message        []byte
	KeyID          string
	SessionID      string
	Curve          string
	PubKeyDer      []byte
	SignatureDER   []byte
	NodesAvailable []string
}

func ShouldJoinPartialSigning(ses *edumpc.Session) {

	pr := promptui.Prompt{Label: fmt.Sprintf("Join the Signing (ID: %s, from:  %s)? (y/n)", "x", "y"), Default: "y"}
	res, _ := pr.Run()
	if res == "y" {
		respsepmsg, err := JoinECDSAPartialSigning(nil, ses) //TODO
		if err != nil {
			Log(err)
			return
		}
		respmsg := new(edumpc.MPCMessage)
		respmsg.Command = AddMeToPartialSig
		respmsg.Protocol = ProtName
		nd, _ := plumbing.GetMPCNode()
		respmsg.SenderID = nd.GetNodeID()
		respmsg.Message = string(respsepmsg)
		ses.Interactive = false
		ses.Respond(respmsg)
	}

}

func JoinECDSAPartialSigning(mpcm *edumpc.MPCMessage, ses *edumpc.Session) ([]byte, error) {
	psmsg := new(ECDSAPartialSignMessage)
	err := json.Unmarshal([]byte(mpcm.Message), psmsg)
	if err != nil {
		return nil, err
	}
	psigmess := new(ECDSAPartialSignMessage)
	psigmess.KeyID = psmsg.KeyID
	for _, n := range currNodes {
		if n.On {
			url := n.Node.URL()
			isNew := true
			for _, otherNodUrl := range psmsg.NodesAvailable {
				if otherNodUrl == url.String() {
					isNew = false
					break
				}
			}
			if isNew {
				psigmess.NodesAvailable = append(psigmess.NodesAvailable, url.String())
			}

		}

	}

	//see if we have any new Nodes to offer
	nmpcm := new(edumpc.MPCMessage)
	psigmess.Message = psmsg.Message
	if len(psigmess.NodesAvailable) > 0 {
		nmpcm.Command = AddMeToPartialSig
		b, _ := json.Marshal(psigmess)
		nmpcm.Message = string(b)
		ses.State = AddMeToPartialSig
		ses.Respond(nmpcm)
	} else {
		Log("Nothing on offer")
	}

	return nil, nil
}

/*
const selectkey = "Select key"
const setmessage = "Set message to sign"
const triggersign = "Initiate signing"

var curkey *tsm.Key
var curkeyid string
var messagetosign string
*/
func TriggerPartialSigningPrompt(mpcn *edumpc.MPCNode) {
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
			sig, err := TriggerPartialSigning(messagetosign, mpcn, curkeyid)
			if err != nil {
				Log(err)
			} else {
				Log("Signature:", hex.EncodeToString(sig))
			}
		default:
			Log("Not implemented")
		}
	}
}

func TriggerPartialSigning(messagetosign string, mpcn *edumpc.MPCNode, keyID string) (signature []byte, err error) {
	if len(messagetosign) == 0 {
		err = fmt.Errorf("Message not set")
		return
	}

	ecC := tsm.NewECDSAClient(tsmC)
	sepsesid := ecC.GenerateSessionID()
	SessionID := "SEP-" + sepsesid
	ses := NewSepiorSession(mpcn, SessionID)
	parSigState := new(ECDSAPartialSignState)
	parSigState.Message = []byte(messagetosign)
	parSigState.NodesAvailable = map[string]string{}

	npcm := new(edumpc.MPCMessage)
	npcm.Command = JoinPartialSig
	psigmess := new(ECDSAPartialSignMessage)
	psigmess.Message = []byte(messagetosign)
	psigmess.SessionID = sepsesid
	psigmess.KeyID = keyID
	//------

	for _, url := range GetActiveClients() {
		parSigState.NodesAvailable[url] = mpcn.PeerID()
		psigmess.NodesAvailable = append(psigmess.NodesAvailable, url)
	}

	ses.State = parSigState
	b, err := json.Marshal(psigmess)
	if err != nil {
		Log(err)
		return
	}
	npcm.Message = string(b)

	coord := make(chan []string)
	CoordChannels[ses.ID] = coord

	//Invite and Wait for collaborators
	ses.Respond(npcm)

outerLoop:
	for {
		select {

		case nurl := <-coord:
			if _, ok := parSigState.NodesAvailable[nurl[0]]; !ok {
				parSigState.NodesAvailable[nurl[0]] = nurl[1]
			}

		case <-time.After(time.Second):
			break outerLoop
		}
	}
	quorum := len(parSigState.NodesAvailable)
	fmt.Printf("Got %v nodes\n", quorum)
	if quorum > 2 {

		go setECDSAPartReassembly(ses)
		for nodeurl, peerid := range parSigState.NodesAvailable {
			if peerid == mpcn.PeerID() {
				ecC := tsm.NewECDSAClient(SingleNodeCilents[nodeurl])
				hash := sha256.Sum256([]byte(messagetosign))
				Log("Local call:", nodeurl, sepsesid, keyID)
				Log(hex.EncodeToString(hash[:]))
				go AsyncECDSAPartial(ecC, sepsesid, keyID, ses.ID, nil, hash[:])

			} else {
				requestPartialSignature(ses, messagetosign, peerid, nodeurl, keyID, sepsesid)
			}

		}

	} else {
		Log("Not enough nodes available on the network")
	}

	return

}

func AsyncECDSAPartial(ecC tsm.ECDSAClient, sepsesid, keyID, eduSesID string, chainPath []uint32, hash []byte) {
	partialSignature, err := ecC.PartialSign(sepsesid, keyID, chainPath, hash)
	if err != nil {
		Log(err)
	} else {
		CoordChannels[eduSesID] <- []string{hex.EncodeToString(partialSignature)}
	}

}

func setECDSAPartReassembly(ses *edumpc.Session) {
	coord := make(chan []string)
	CoordChannels[ses.ID] = coord
	defer delete(CoordChannels, ses.ID)
	partialSig := [][]byte{}

	for {
		select {
		case parsig := <-coord:
			Log("Assemly received:", parsig)
			bts, err := hex.DecodeString(parsig[0])
			if err != nil {
				Log(err)
				continue
			}
			partialSig = append(partialSig, bts)
			if len(partialSig) > 2 { //??Threshold
				signature, _, err := tsm.ECDSAFinalize(partialSig...)
				Log("Assembly result:")
				Log(err)
				Log(hex.EncodeToString(signature))
				//ses := edumpc.
				return
			}
		case <-time.After(20 * time.Second):
			Log("Timeout reassembling")
			return

		}
	}

}

func requestPartialSignature(ses *edumpc.Session, messtosign, peerid, url, keyID, sessionID string) {
	st := ses.State.(*ECDSAPartialSignState)
	Log("Message to sign:", messtosign)
	Log("To:", peerid)
	Log("node:", url)
	Log(time.Now())
	mpcm := new(edumpc.MPCMessage)
	mpcm.Command = DoPartialSig
	mpcm.To = peerid
	psigm := new(ECDSAPartialSignMessage)
	psigm.Message = st.Message
	psigm.NodesAvailable = []string{url}
	psigm.SessionID = sessionID
	psigm.KeyID = keyID
	//psigm.NodesAvailable[peerid] = url

	mpcm.SetMessage(psigm)
	ses.Respond(mpcm)

}

func FullfillPartialSig(mpcm *edumpc.MPCMessage, ses *edumpc.Session) {
	psmsg := new(ECDSAPartialSignMessage)
	json.Unmarshal([]byte(mpcm.Message), psmsg)
	if mpcm.To != ses.Node.PeerID() {
		Log("Not for me...")
	} else {
		if mpcm.Command != DoPartialSig {
			fmt.Print("Messed up command pint 1234")
			return
		}
		msg := new(ECDSAPartialSignMessage)
		err := mpcm.CastMessage(msg)
		if err != nil {
			Log(err)
			return
		}
		tsmSC, ok := SingleNodeCilents[msg.NodesAvailable[0]]
		if !ok {
			Log("No client at 2345. This should not have happened")
		}
		eC := tsm.NewECDSAClient(tsmSC)
		hash := sha256.Sum256(msg.Message)
		Log("Remote signing:", msg.NodesAvailable[0], msg.SessionID, msg.KeyID)
		Log(hex.EncodeToString(hash[:]))
		Log(time.Now())
		partialSignature, err := eC.PartialSign(msg.SessionID, msg.KeyID, nil, hash[:])

		rmpcm := new(edumpc.MPCMessage)
		rmpcm.Command = ReassembleECDSASig
		rmsg := new(ECDSAPartialSignMessage)
		rmsg.SessionID = msg.SessionID
		rmsg.KeyID = msg.KeyID
		rmsg.SignatureDER = partialSignature
		rmpcm.SetMessage(rmsg)
		ses.Respond(rmpcm)

		//fmt.Println(err, hex.EncodeToString(partialSignature))

	}
}
