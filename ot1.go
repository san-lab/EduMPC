package main

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/manifoldco/promptui"
)

//TODO role within the Session
//var role string

//var msg1 string
//var msg2 string

// var A_sender = &ECPoint{}
// var A_receiver = &ECPoint{}
//var a []byte

// var B_sender = &ECPoint{}
// var B_receiver = &ECPoint{}
//var b []byte

//var E = &EncryptedValues{}

type OT1State struct {
	Role        string
	Msg1        string
	Msg2        string
	A           *ECPoint
	ABytes      []byte
	B           *ECPoint
	BBytes      []byte
	Ciphertexts *EncryptedValues
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

func InitNewOt1(mpcn *MPCNode) {
	id := "OT1-" + uuid.NewString() //TODO Randomize

	ses := NewOt1Session(mpcn, id)
	ots := (ses.State).(*OT1State)
	ots.Role = "recipient"

	mpcm := new(MPCMessage)
	mpcm.Protocol = ot1
	mpcm.Command = "join"
	mpcn.Respond(mpcm, ses)

	return
}

func NewOt1Session(mpcn *MPCNode, sessionID string) *Session {
	ses := new(Session)
	ses.ID = sessionID
	ses.Type = ot1
	ses.HandleMessage = HandleOt1Message
	ses.Details = ShowHistory
	ses.Interactive = true
	ses.NextPrompt = Ot1Prompt
	ots := NewOT1State()
	ots.Role = "sender"
	ses.State = ots

	ses.ID = sessionID
	mpcn.sessions[ses.ID] = ses
	return ses
}

func Ot1Prompt(mpcn *MPCNode, ses *Session) {

}

func Ot1PromptJoin(mpcn *MPCNode, ses *Session) {
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
		delete(mpcn.sessions, ses.ID)
	case "Yes":
		prP := promptui.Prompt{Label: "Message 1"}
		ots.Msg1, _ = prP.Run()
		prP = promptui.Prompt{Label: "Message 2"}
		ots.Msg2, _ = prP.Run()

		ots.A, ots.ABytes, _ = senderInit(myCurve)
		ABytes, _ := json.Marshal(ots.A)

		mpcm := new(MPCMessage)
		mpcm.Message = ABytes
		mpcm.Command = "choose"
		mpcn.Respond(mpcm, ses)
		ses.Interactive = false
	}
}

func Ot1PromptChoice(mpcn *MPCNode, ses *Session) {
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
		ots.B, ots.BBytes, _ = receiverPicks(myCurve, ots.A, 0)
	case "msg2":
		ots.B, ots.BBytes, _ = receiverPicks(myCurve, ots.A, 1)

	}
	BBytes, _ := json.Marshal(ots.B)

	mpcm := new(MPCMessage)
	mpcm.Message = BBytes
	mpcm.Command = "transfer"
	mpcn.Respond(mpcm, ses)
	ses.Interactive = false
}

func Ot1PromptTransfer(mpcn *MPCNode, ses *Session) {
	ots := ses.State.(*OT1State)
	e0, nonce0, e1, nonce1, _ := senderEncrypts(myCurve, ots.A, ots.B, ots.ABytes, []byte(ots.Msg1), []byte(ots.Msg2))
	E_tmp := EncryptedValues{E0: e0, Nonce0: nonce0, E1: e1, Nonce1: nonce1}
	EBytes, _ := json.Marshal(E_tmp)

	mpcm := new(MPCMessage)
	mpcm.Message = EBytes
	mpcm.Command = "decrypt"
	mpcn.Respond(mpcm, ses)
	ses.Interactive = false
	delete(mpcn.sessions, ses.ID)

}

func Ot1PromptDecrypt(mpcn *MPCNode, ses *Session) {
	ots := ses.State.(*OT1State)
	m, _ := receiverDecrypts(myCurve, ots.A, ots.BBytes, ots.Ciphertexts.E0, ots.Ciphertexts.Nonce0, ots.Ciphertexts.E1, ots.Ciphertexts.Nonce1)
	fmt.Println("Decrypted message:", string(m))
	delete(mpcn.sessions, ses.ID)
}

func HandleOt1Message(mpcm *MPCMessage, ses *Session) {
	ots := ses.State.(*OT1State)
	switch mpcm.Command {
	case "join":
		ses.Interactive = true
		ses.NextPrompt = Ot1PromptJoin
	case "choose":
		ses.Interactive = true
		json.Unmarshal(mpcm.Message, ots.A) //TODO A in session struct
		ses.NextPrompt = Ot1PromptChoice
	case "transfer":
		ses.Interactive = true
		json.Unmarshal(mpcm.Message, ots.B)
		ses.NextPrompt = Ot1PromptTransfer
	case "decrypt":
		ses.Interactive = true
		json.Unmarshal(mpcm.Message, ots.Ciphertexts)
		ses.NextPrompt = Ot1PromptDecrypt
	default:
		fmt.Println("we shouldnt be here...")

	}

}
