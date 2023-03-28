package main

import (
	"fmt"
)

type Session struct {
	ID                string
	Type              Protocol
	HandleMessage     func(*MPCMessage, *Session)
	Details           func(*Session)
	Interactive       bool
	PendingUserAction bool
	NextPrompt        func(*MPCNode, *Session)
	History           []*MPCMessage
	Status            string
	Node              *MPCNode
	State             interface{}
}

func (mpcn *MPCNode) NewSession(protocol Protocol, sessionID string) *Session {
	switch protocol {
	case chat:
		return NewChatSession(mpcn, sessionID)
	case ot1:
		return NewOt1Session(mpcn, sessionID)
	case PM2A:
		return NewRecPM2ASession(mpcn, sessionID)
	case PM2Att:
		return NewRecPM2AttSession(mpcn, sessionID)
	default:
		return NewDumbSession(mpcn, sessionID)
	}

	fmt.Println("We should not be here...")
	return nil
}

func (ses *Session) SessionHandle(msg *MPCMessage) {
	if ses.History == nil {
		ses.History = []*MPCMessage{}
	}
	ses.History = append(ses.History, msg)
	ses.HandleMessage(msg, ses)
}

func NewDumbSession(mpcn *MPCNode, sessionID string) *Session {
	ses := new(Session)
	ses.ID = sessionID
	ses.Type = dumb
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

func init() {
	Protocols = []Protocol{chat, dumb, ot1, PM2A, PM2Att}
}

func ShowHistory(ses *Session) {
	fmt.Println(ses.ID, "history:")
	for _, msg := range ses.History {

		fmt.Println(msg.SenderID, msg.Command, string(msg.Message))
	}
}

var Protocols []Protocol
