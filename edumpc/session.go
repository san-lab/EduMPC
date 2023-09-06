package edumpc

import (
	"fmt"
	"sync"
)

type Session struct {
	ID                string
	Protocol          Protocol
	HandleMessage     func(*MPCMessage, *Session)
	Details           func(*Session)
	Interactive       bool
	PendingUserAction bool
	NextPrompt        func(*Session)
	History           []*MPCMessage
	messages          map[string]bool
	Status            string
	Node              *MPCNode
	State             interface{}
}

func (ses *Session) Respond(msg *MPCMessage) {

	ses.Node.SendMsg(msg, ses)
}

func (ses *Session) LastMessage() *MPCMessage {
	l := len(ses.History)
	if l == 0 {
		return nil
	}
	return ses.History[l-1]
}

func (mpcn *MPCNode) NewIncomingSession(protocol Protocol, sessionID string) *Session {
	if proth, ok := Protocols[protocol]; ok {
		return proth.NewSessionTriggered(mpcn, sessionID)
	} else {
		fmt.Println("Unknown protocol:", protocol)
		return NewDumbSession(mpcn, sessionID)
	}
}

var sesmux = &sync.Mutex{}

func (ses *Session) SessionHandle(msg *MPCMessage) {
	sesmux.Lock()
	defer sesmux.Unlock()
	if ses.History == nil {
		ses.History = []*MPCMessage{}
	}
	if ses.messages == nil {
		ses.messages = map[string]bool{}
	}
	//Check if duplicate
	if ses.messages[msg.MessageID] {
		fmt.Println("duplicate message", msg.MessageID)
		return
	}
	ses.History = append(ses.History, msg)
	ses.messages[msg.MessageID] = true
	ses.HandleMessage(msg, ses)
}

func NewDumbSession(mpcn *MPCNode, sessionID string) *Session {
	ses := new(Session)
	ses.ID = sessionID
	ses.Protocol = dumb
	ses.HandleMessage = func(*MPCMessage, *Session) {}
	ses.Details = func(*Session) { fmt.Println("No details to show") }
	ses.Interactive = false
	ses.NextPrompt = nil
	mpcn.sessions[ses.ID] = ses
	ses.Node = mpcn
	return ses
}

type Protocol string

const chat = Protocol("chat")
const dumb = Protocol("Unknown protocol")
const ot1 = Protocol("ot1")
const PM2A = Protocol("Paillier M2A") //Paillier Multi-to-Additive
const PM2Att = Protocol("Fireblocks attack")
const Lin = Protocol("Lindell")

func init() {
	Protocols[chat] = &SessionHandler{InitNewChat, NewChatSession}
	Protocols[dumb] = &SessionHandler{func(n *MPCNode) { fmt.Println("Dumb") }, NewDumbSession}
	Protocols[ot1] = &SessionHandler{InitNewOt1, NewOt1Session}
	Protocols[PM2A] = &SessionHandler{InitNewPM2A, NewRecPM2ASession}
	Protocols[PM2Att] = &SessionHandler{InitNewPM2Att, NewRecPM2AttSession}
	Protocols[Lin] = &SessionHandler{InitNewLin, NewRecLinSession}
}

func ShowHistory(ses *Session) {
	fmt.Println(ses.ID, "history:")
	for _, msg := range ses.History {

		fmt.Println(msg.SenderID, msg.Command, string(msg.Message))
	}
}

type SessionHandler struct {
	NewSessionUI        func(*MPCNode)
	NewSessionTriggered func(mpcn *MPCNode, sessionID string) *Session
}

var Protocols = map[Protocol]*SessionHandler{}
