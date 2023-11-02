package edumpc

import (
	"fmt"
	"sync"
	"time"
)

type Session struct {
	ID                string
	Protocol          Protocol
	HandleMessage     func(*MPCMessage, *Session)
	Details           func(*Session)
	Interactive       bool
	PendingUserAction bool
	NextPrompt        func(*Session)
	History           []MessageHistoryEntry
	messages          map[string]bool
	Status            string
	Inactive          bool
	Node              *MPCNode
	State             interface{}
}

type MessageHistoryEntry struct {
	Timestamp time.Time
	Message   *MPCMessage
}

func (ses *Session) Respond(msg *MPCMessage) {

	ses.Node.SendMsg(msg, ses)
}

func (ses *Session) Respond2(command string, msg interface{}) {
	mpcm := new(MPCMessage)
	mpcm.Command = command
	err := mpcm.SetMessage(msg)
	if err != nil {
		fmt.Println(err)
	}
	ses.Respond(mpcm)
}

func (ses *Session) LastMessage() *MPCMessage {
	l := len(ses.History)
	if l == 0 {
		return nil
	}
	return ses.History[l-1].Message
}

func (mpcn *MPCNode) NewIncomingSession(protocol Protocol, sessionID string) *Session {
	if proth, ok := Protocols[protocol]; ok {
		return proth.NewSessionTriggered(mpcn, sessionID)
	} else {
		fmt.Println("Unknown protocol:", protocol)
		fmt.Println(Protocols)
		return NewDumbSession(mpcn, sessionID)
	}
}

var sesmux = &sync.Mutex{}

func (ses *Session) SessionHandle(msg *MPCMessage) {
	sesmux.Lock()
	defer sesmux.Unlock()
	if ses.History == nil {
		ses.History = []MessageHistoryEntry{}
	}
	if ses.messages == nil {
		ses.messages = map[string]bool{}
	}
	//Check if duplicate
	if ses.messages[msg.MessageID] {
		fmt.Println("duplicate message", msg.MessageID)
		//sesmux.Unlock()
		return

	}
	ses.History = append(ses.History, MessageHistoryEntry{time.Now(), msg})
	ses.messages[msg.MessageID] = true
	//sesmux.Unlock()
	ses.HandleMessage(msg, ses) // Take this out of Mutex
}

func NewDumbSession(mpcn *MPCNode, sessionID string) *Session {
	ses := new(Session)
	ses.ID = sessionID
	ses.Protocol = dumb
	ses.HandleMessage = func(*MPCMessage, *Session) {}
	ses.Details = ShowDetails
	ses.Interactive = false
	ses.NextPrompt = nil
	mpcn.sessions[ses.ID] = ses
	ses.Node = mpcn
	return ses
}

type Protocol string

// const chat = Protocol("chat")
const dumb = Protocol("Unknown protocol")

func init() {

	Protocols[dumb] = &SessionHandler{func(n *MPCNode) { fmt.Println("Dumb") }, NewDumbSession, nil, nil}

}

func ShowHistory(ses *Session) {
	fmt.Println(ses.ID, "history:")
	for _, msgh := range ses.History {
		msg := msgh.Message
		fmt.Println(msgh.Timestamp)
		fmt.Println(msg.SenderID, msg.Command, msg.MessageString())
	}
}

func ShowDetails(ses *Session) {
	fmt.Println("ID:\t", ses.ID)
	_, ok := Protocols[ses.Protocol]
	fmt.Println("Protocol\t:", ses.Protocol, "known:", ok)
	fmt.Println("Status\t:", ses.Status)
}

type SessionHandler struct {
	NewSessionUI        func(*MPCNode)
	NewSessionTriggered func(mpcn *MPCNode, sessionID string) *Session
	SaveSession         func(*Session) ([]byte, error)
	RestoreSession      func(*Session, []byte) error
}

var Protocols = map[Protocol]*SessionHandler{}
