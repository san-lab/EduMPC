package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
)

// ChatRoomBufSize is the number of incoming messages to buffer for each topic.
const ChatRoomBufSize = 128

// MPCNode represents a subscription to a single PubSub topic. Messages
// can be published to the topic with MPCNode.Publish, and received
// messages are pushed to the Messages channel.
type MPCNode struct {
	// Messages is a channel of messages received from other peers in the chat room
	ctx      context.Context
	ps       *pubsub.PubSub
	topic    *pubsub.Topic
	sub      *pubsub.Subscription
	self     peer.ID
	sessions map[string]*Session
}

type Command string

const initialize = Command("initialize")
const challenge = Command("challenge")
const response = Command("response")

// MPCMessage gets converted to/from JSON and sent in the body of pubsub messages.
type MPCMessage struct {
	Message   []byte
	Protocol  Protocol
	Command   Command
	SenderID  string
	SessionID string
	To        string // peer.ID, to be used when targetting a specific peer
}

// readLoop pulls messages from the pubsub topic and pushes them onto the Messages channel.
func (mpcn *MPCNode) readLoop() {
	for {
		msg, err := mpcn.sub.Next(mpcn.ctx)
		if err != nil {
			log.Fatalln(err)
			return
		}
		// only forward messages delivered by others
		if msg.ReceivedFrom == mpcn.self {
			continue
		}

		mpcn.ProcessMessage(msg)

	}
}

func (mpcn *MPCNode) ProcessMessage(msg *pubsub.Message) {
	if mpcn.sessions == nil {
		mpcn.sessions = map[string]*Session{}
	}
	mpcmsg := new(MPCMessage)
	err := json.Unmarshal(msg.Data, mpcmsg)
	if err != nil {
		fmt.Println("Bad frame:", err)
		return
	}
	var session *Session
	var ok bool
	session, ok = mpcn.sessions[mpcmsg.SessionID]
	if !ok {
		session = mpcn.NewSession(mpcmsg.Protocol, mpcmsg.SessionID)
	}
	session.SessionHandle(mpcmsg)
}

func (mpcn *MPCNode) Respond(mpcmsg *MPCMessage, ses *Session) {

	mpcmsg.SenderID = mpcn.self.String()
	mpcmsg.SessionID = ses.ID
	ses.History = append(ses.History, mpcmsg)
	b, _ := json.Marshal(mpcmsg)
	mpcn.topic.Publish(context.Background(), b)

}

// tries to subscribe to the PubSub topic for the room name, returning
// an MPCNode on success.
func JoinMPCNet(ctx context.Context, ps *pubsub.PubSub, selfID peer.ID, roomName string) (*MPCNode, error) {
	// join the pubsub topic
	topic, err := ps.Join(MPCNET)
	if err != nil {
		return nil, err
	}

	// and subscribe to it
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, err
	}

	mpcn := &MPCNode{
		ctx:      ctx,
		ps:       ps,
		topic:    topic,
		sub:      sub,
		self:     selfID,
		sessions: map[string]*Session{},
	}

	// start reading messages from the subscription in a loop
	go mpcn.readLoop()
	return mpcn, nil
}
