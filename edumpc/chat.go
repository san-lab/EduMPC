package edumpc

import (
	"fmt"

	"github.com/manifoldco/promptui"
)

func NewChatSession(mpcn *MPCNode, sessionID string) *Session {
	ses := new(Session)
	ses.ID = sessionID
	ses.Protocol = chat
	ses.HandleMessage = HandleChatMessage
	ses.Details = ShowHistory
	ses.Interactive = true
	ses.NextPrompt = ChatPrompt
	ses.ID = sessionID
	mpcn.sessions[ses.ID] = ses
	ses.Node = mpcn
	return ses
}

func HandleChatMessage(mpcm *MPCMessage, ses *Session) {

}

func ChatPrompt(ses *Session) {
	/*
		var last string
		if l := len(ses.History); l > 0 {
			last = ses.History[l-1].SenderID + ": " + string(ses.History[l-1].Message)
		} else {
			last = "New chat"
		}
	*/
	pr := promptui.Prompt{Label: ses.ID} //fmt.Sprintf("Chat %s\n%s", last)}
	txt, _ := pr.Run()
	mpcm := new(MPCMessage)
	mpcm.Message = txt
	ses.Respond(mpcm)

}

func InitNewChat(mpcn *MPCNode) {
	pr := promptui.Prompt{Label: "New Chat ID"}
	id, _ := pr.Run()
	ses := NewChatSession(mpcn, id)
	pr = promptui.Prompt{Label: fmt.Sprintf("Initial message for chat %s", id)}
	txt, _ := pr.Run()
	mpcm := new(MPCMessage)
	mpcm.Message = txt
	mpcm.Protocol = chat
	ses.Respond(mpcm)

}
