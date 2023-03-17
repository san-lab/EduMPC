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

var A = &ECPoint{}
var a []byte

var B = &ECPoint{}
var b []byte



func InitNewOt1(mpcn *MPCNode) {
	id := "ot1ID"

	ses := NewOt1Session(mpcn, id)
	role = "recepient"

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
//	ses.NextPrompt = Ot1PromptJoin

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

		Atmp, _, _ := senderInit(myCurve)
		fmt.Println("Atmp:", *Atmp, Atmp.X, Atmp.Y)

		mpcm := new(MPCMessage)
		ABytes, err := json.Marshal(*Atmp)

		fmt.Println("lenAbytes:", len(ABytes))

		fmt.Println("err:", err)

		test := ECPoint{}
		json.Unmarshal(ABytes, &test)
		fmt.Println("test:", test)


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
		B, b, _ = receiverPicks(myCurve, A, 0)
	case "msg2":
		B, b, _ = receiverPicks(myCurve, A, 1)

	}
	mpcm := new(MPCMessage)
	BBytes , _ := json.Marshal(*B)
	mpcm.Message = BBytes
	mpcm.Command = "transfer"
	mpcn.Respond(mpcm, ses)
	ses.Interactive = false
}


func HandleOt1Message(mpcm *MPCMessage, ses *Session) {
	switch mpcm.Command {
	case "join":
		ses.Interactive = true
		ses.NextPrompt = Ot1PromptJoin
	case "choose":
		ses.Interactive = true
		err := json.Unmarshal(mpcm.Message, A)
		fmt.Println("errorrrrr:" , err)
		ses.NextPrompt = Ot1PromptChoice
	case "transfer":
		fmt.Println("we got here yay!")
	default:
	}

}
