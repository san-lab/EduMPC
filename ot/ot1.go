package ot

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/manifoldco/promptui"
	"github.com/san-lab/EduMPC/edumpc"
)

type OT1State struct {
	Role        string
	Msg1        string
	Msg2        string
	Choice      int
	A           *ECPoint
	Priv_a      []byte
	B           *ECPoint
	Priv_b      []byte
	Ciphertexts *EncryptedValues
	Plaintext   []byte
}

func NewOT1State() *OT1State {
	ots := new(OT1State)
	ots.A = &ECPoint{}
	ots.B = &ECPoint{}
	ots.Ciphertexts = &EncryptedValues{}
	return ots
}

type EncryptedValues struct {
	E0     []byte `"json: e0"`
	Nonce0 []byte `"json: nonce0"`
	E1     []byte `"json: e1"`
	Nonce1 []byte `"json: nonce1"`
}

func InitNewOt1(mpcn *edumpc.MPCNode) {
	id := "OT1-" + uuid.NewString() //TODO Randomize

	ses := NewOt1Session(mpcn, id)
	ots := (ses.State).(*OT1State)
	ots.Role = "recipient"

	mpcm := new(edumpc.MPCMessage)
	mpcm.Protocol = ProtName
	mpcm.Command = "join"
	ses.Respond(mpcm)

	return
}

const ProtName = edumpc.Protocol("ot1")

var SessionHandler = edumpc.SessionHandler{InitNewOt1, NewOt1Session, Save, Load}

func Save(ses *edumpc.Session) ([]byte, error) { return nil, nil }
func Load(ses *edumpc.Session, b []byte) error { return nil }

func Init(mpcn *edumpc.MPCNode) {
	edumpc.Protocols[ProtName] = &SessionHandler
}

func NewOt1Session(mpcn *edumpc.MPCNode, sessionID string) *edumpc.Session {
	ses := new(edumpc.Session)
	ses.ID = sessionID
	ses.Protocol = ProtName
	ses.HandleMessage = HandleOt1Message
	ses.Details = PrintState
	ses.Interactive = true
	ses.NextPrompt = Ot1Prompt
	ots := NewOT1State()
	ots.Role = "sender"
	ses.State = ots
	ses.Status = "awaiting peer"
	ses.ID = sessionID
	mpcn.NewLocalSession(ses.ID, ses)
	ses.Node = mpcn
	return ses
}

func PrintState(ses *edumpc.Session) {
	ots, _ := ses.State.(*OT1State)
	fmt.Println("Role:", ots.Role)
	fmt.Println("Status:", ses.Status)
	fmt.Println("Choice:", ots.Choice)
	fmt.Println("A:", ots.A)
	fmt.Println("a:", ots.Priv_a)
	fmt.Println("B:", ots.B)
	fmt.Println("b:", ots.Priv_b)
	fmt.Println("Ciphertexts:", ots.Ciphertexts)
	fmt.Println("Plaintext:", string(ots.Plaintext))
}

func Ot1Prompt(ses *edumpc.Session) {

}

const up = "up"

func Ot1PromptJoin(ses *edumpc.Session) {
	ots := ses.State.(*OT1State)
	items := []string{"Yes", "No", up}
	pr := promptui.Select{Label: "Accept OT1 invitation",
		Items: items,
	}
	_, res, _ := pr.Run()
	switch res {
	case up:
		return
	case "No":
		ses.Inactive = true
		//delete(ses.Node.sessions, ses.ID)
	case "Yes":
		prP := promptui.Prompt{Label: "Message 1"}
		ots.Msg1, _ = prP.Run()
		prP = promptui.Prompt{Label: "Message 2"}
		ots.Msg2, _ = prP.Run()

		ots.A, ots.Priv_a, _ = senderInit(myCurve)
		//ABytes, _ := json.Marshal(ots.A)

		//mpcm := new(edumpc.MPCMessage)
		//mpcm.Message = string(ABytes)
		//mpcm.SetMessage(ots.A)
		//mpcm.Command = "choose"
		ses.Respond2("choose", ots.A)
		ses.Interactive = false
		ses.Status = "joined"
	}
}

func Ot1PromptChoice(ses *edumpc.Session) {
	ots := ses.State.(*OT1State)
	items := []string{"msg1", "msg2", up}
	pr := promptui.Select{Label: "Select message",
		Items: items,
	}
	_, res, _ := pr.Run()
	switch res {
	case up:
		return
	case "msg1":
		ots.Choice = 1
		ots.B, ots.Priv_b, _ = receiverPicks(myCurve, ots.A, 1)
	case "msg2":
		ots.Choice = 2
		ots.B, ots.Priv_b, _ = receiverPicks(myCurve, ots.A, 2)

	}
	BBytes, _ := json.Marshal(ots.B)

	mpcm := new(edumpc.MPCMessage)
	mpcm.Message = string(BBytes)
	mpcm.Command = "transfer"
	ses.Respond(mpcm)
	ses.Interactive = false
	ses.Status = "msg chosen"
}

func Ot1PromptTransfer(ses *edumpc.Session) {
	ots := ses.State.(*OT1State)
	e0, nonce0, e1, nonce1, _ := senderEncrypts(myCurve, ots.A, ots.B, ots.Priv_a, []byte(ots.Msg1), []byte(ots.Msg2))
	ots.Ciphertexts = &EncryptedValues{E0: e0, Nonce0: nonce0, E1: e1, Nonce1: nonce1}
	EBytes, _ := json.Marshal(ots.Ciphertexts)

	mpcm := new(edumpc.MPCMessage)
	mpcm.Message = string(EBytes)
	mpcm.Command = "decrypt"
	ses.Respond(mpcm)
	ses.Interactive = false
	ses.Status = "done"
	//	delete(mpcn.sessions, ses.ID)

}

func Ot1PromptDecrypt(ses *edumpc.Session) {
	ots := ses.State.(*OT1State)
	m, _ := receiverDecrypts(myCurve, ots.A, ots.Priv_b, ots.Ciphertexts.E0, ots.Ciphertexts.Nonce0, ots.Ciphertexts.E1, ots.Ciphertexts.Nonce1)
	ots.Plaintext = m
	fmt.Println("Decrypted message:", string(m))
	ses.Status = "done"
	// delete(mpcn.sessions, ses.ID)
}

func HandleOt1Message(mpcm *edumpc.MPCMessage, ses *edumpc.Session) {
	ots := ses.State.(*OT1State)
	switch mpcm.Command {
	case "join":
		ses.Interactive = true
		ses.NextPrompt = Ot1PromptJoin
	case "choose":
		ses.Interactive = true
		json.Unmarshal([]byte(mpcm.Message), ots.A)
		ses.NextPrompt = Ot1PromptChoice
	case "transfer":
		ses.Interactive = false
		json.Unmarshal([]byte(mpcm.Message), ots.B)
		Ot1PromptTransfer(ses)
	case "decrypt":
		ses.Interactive = false
		json.Unmarshal([]byte(mpcm.Message), ots.Ciphertexts)
		Ot1PromptDecrypt(ses)
	default:
		fmt.Println("we shouldnt be here...")

	}

}
