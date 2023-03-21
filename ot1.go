package main

import (
	"fmt"
	"encoding/json"
	"github.com/manifoldco/promptui"
)

//TODO role within the Session
var role string

var msg1 string
var msg2 string

var A_sender = &ECPoint{}
var A_receiver = &ECPoint{}
var a []byte

var B_sender = &ECPoint{}
var B_receiver = &ECPoint{}
var b []byte

var E = &EncryptedValues{}

type EncryptedValues struct {
	E0 []byte     `"json: e0"`
	Nonce0 []byte `"json: nonce0"`
	E1 []byte     `"json: e1"`
	Nonce1 []byte `"json: nonce1"`
}

func InitNewOt1(mpcn *MPCNode) {
	id := "ot1ID" //TODO Randomize

	ses := NewOt1Session(mpcn, id)
	role = "recipient"

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
	ses.ID = sessionID
	mpcn.sessions[ses.ID] = ses
	role = "sender"
	return ses
}

func Ot1Prompt(mpcn *MPCNode, ses *Session) {

}

func Ot1PromptJoin(mpcn *MPCNode, ses *Session) {
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
		msg1, _ = prP.Run()
		prP = promptui.Prompt{Label: "Message 2"}
		msg2, _ = prP.Run()

		A_sender, a, _ = senderInit(myCurve)
		ABytes, _ := json.Marshal(*A_sender)

		mpcm := new(MPCMessage)
		mpcm.Message = ABytes
		mpcm.Command = "choose"
		mpcn.Respond(mpcm, ses)
		ses.Interactive = false
	}
}


func Ot1PromptChoice(mpcn *MPCNode, ses *Session) {
	items := []string{"msg1", "msg2", up}
	pr := promptui.Select{Label: "Select message",
		Items: items,
	}
	_, res, _ := pr.Run()
	switch res {
	case up:
		return
	case "msg1":
		B_receiver, b, _ = receiverPicks(myCurve, A_receiver, 0)
	case "msg2":
		B_receiver, b, _ = receiverPicks(myCurve, A_receiver, 1)

	}
	BBytes , _ := json.Marshal(*B_receiver)

	mpcm := new(MPCMessage)
	mpcm.Message = BBytes
	mpcm.Command = "transfer"
	mpcn.Respond(mpcm, ses)
	ses.Interactive = false
}

func Ot1PromptTransfer(mpcn *MPCNode, ses *Session) {
	e0, nonce0, e1, nonce1, _ := senderEncrypts(myCurve, A_sender, B_sender, a, []byte(msg1), []byte(msg2))
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
	m, _ := receiverDecrypts(myCurve, A_receiver, b, E.E0, E.Nonce0, E.E1, E.Nonce1)
	fmt.Println("Decrypted message:", string(m))
	delete(mpcn.sessions, ses.ID)
}


func HandleOt1Message(mpcm *MPCMessage, ses *Session) {
	switch mpcm.Command {
	case "join":
		ses.Interactive = true
		ses.NextPrompt = Ot1PromptJoin
	case "choose":
		ses.Interactive = true
		json.Unmarshal(mpcm.Message, A_receiver) //TODO A in session struct
		ses.NextPrompt = Ot1PromptChoice
	case "transfer":
		ses.Interactive = true
		json.Unmarshal(mpcm.Message, B_sender)
		ses.NextPrompt = Ot1PromptTransfer
	case "decrypt":
		ses.Interactive = true
		json.Unmarshal(mpcm.Message, E)
		ses.NextPrompt = Ot1PromptDecrypt
	default:
		fmt.Println("we shouldnt be here...")

	}

}
