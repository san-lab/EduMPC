package chat

import (
	"fmt"

	"github.com/manifoldco/promptui"
	"github.com/san-lab/EduMPC/edumpc"
)

const ProtName = edumpc.Protocol("Chat")

var SessionHandler = edumpc.SessionHandler{InitNewChat, NewChatSession, Save, Load}

func Save(ses *edumpc.Session) ([]byte, error) { return nil, nil }
func Load(ses *edumpc.Session, b []byte) error { return nil }

func NewChatSession(mpcn *edumpc.MPCNode, sessionID string) *edumpc.Session {
	ses := new(edumpc.Session)
	ses.ID = sessionID
	ses.Protocol = ProtName
	ses.HandleMessage = HandleChatMessage
	ses.Details = edumpc.ShowHistory
	ses.Interactive = true
	ses.NextPrompt = ChatPrompt
	ses.ID = sessionID
	//mpcn.sessions[ses.ID] = ses
	mpcn.NewLocalSession(sessionID, ses)
	ses.Node = mpcn
	return ses
}

func HandleChatMessage(mpcm *edumpc.MPCMessage, ses *edumpc.Session) {

}

func ChatPrompt(ses *edumpc.Session) {
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
	//mpcm := new(edumpc.MPCMessage)
	//mpcm.SetMessage(txt)
	ses.Respond2("", txt)

}

func InitNewChat(mpcn *edumpc.MPCNode) {
	pr := promptui.Prompt{Label: "New Chat ID"}
	id, _ := pr.Run()
	ses := NewChatSession(mpcn, id)
	pr = promptui.Prompt{Label: fmt.Sprintf("Initial message for chat %s", id)}
	txt, _ := pr.Run()
	mpcm := new(edumpc.MPCMessage)
	mpcm.SetMessage(txt)
	mpcm.Protocol = ProtName
	ses.Respond(mpcm)

}

func Init(*edumpc.MPCNode) {
	edumpc.Protocols[ProtName] = &SessionHandler
}
