package edumpc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/google/uuid"
	"github.com/manifoldco/promptui"
)

type LinKeyGenMessage struct {
	PubShare *ECPoint
	EncShare *big.Int
	Pub      *PaillierPub
}

type LinKeyGenEndMessage struct {
	PubShare *ECPoint
	PubEcdsa *ecdsa.PublicKey
}

type LinPreSignMessage struct {
	PubPartialNonce *ECPoint
	Message         string
}

type LinState struct {
	Role             string
	Priv             *PaillierPriv
	Pub              *PaillierPub
	PubEcdsa         *ecdsa.PublicKey
	ShareA           *big.Int
	ShareB           *big.Int
	EncShareB        *big.Int
	PubShareA        *ECPoint
	PubShareB        *ECPoint
	Message          string
	PartialNonceA    *big.Int
	PartialNonceB    *big.Int
	PubNonce         *ECPoint
	PubPartialNonceA *ECPoint
	PubPartialNonceB *ECPoint
	D                *big.Int
	S                *big.Int
}

func NewLinState() *LinState {
	st := new(LinState)
	return st
}

func PrintLinState(ses *Session) {
	fmt.Println("Printing state...")
	st := (ses.State).(*LinState)
	fmt.Println("Role:", st.Role)
	fmt.Println("Private key:", st.Priv != nil)
	n := big.NewInt(0)
	if st.Pub != nil {
		n = st.Pub.N
	}
	fmt.Println("Pub N:", n)
	fmt.Println("PubEcdsa:", st.PubEcdsa)
	fmt.Println("Secret share A:", st.ShareA)
	fmt.Println("Secret share B:", st.ShareB)
	fmt.Println("EncShareB:", st.EncShareB)
	fmt.Println("PubShareA:", st.PubShareA)
	fmt.Println("PubShareB:", st.PubShareB)
	fmt.Println("Message:", st.Message)
	fmt.Println("PartialNonceA:", st.PartialNonceA)
	fmt.Println("PartialNonceB:", st.PartialNonceB)
	fmt.Println("PubNonce:", st.PubNonce)
	fmt.Println("PubPartialNonceA:", st.PubPartialNonceA)
	fmt.Println("PubPartialNonceB:", st.PubPartialNonceB)
	fmt.Println("D:", st.D)
	fmt.Println("S:", st.S)
}

func LinDetails(ses *Session) {
	PrintLinState(ses)
	fmt.Println(ses.History)
}

func InitNewLin(mpcn *MPCNode) {
	var err error
	sid := "Lin-" + uuid.NewString()
	ses := NewSenderLinSession(mpcn, sid)
	st := (ses.State).(*LinState)

	st.ShareB = PromptForNumber("ECDSA private key share", "33")

	b := PromptForNumber("Bits for paillier key:", "1024")
	bits := int(b.Int64())
	st.Priv, st.Pub = GenerateNiceKeyPair(bits)

	st.EncShareB = st.Pub.Encrypt(st.ShareB)
	Xs_x, Xs_y := CurveLindell.ScalarBaseMult(st.ShareB.Bytes())
	st.PubShareB = &ECPoint{Xs_x, Xs_y}

	mpcm := new(MPCMessage)
	mpcm.Command = "keygen_join"
	msg := &LinKeyGenMessage{}
	msg.Pub = st.Pub
	msg.EncShare = st.EncShareB
	msg.PubShare = st.PubShareB

	tmp, err := json.Marshal(msg)
	mpcm.Message = string(tmp)
	if err != nil {
		fmt.Println(err)
	}

	mpcm.Protocol = Lin
	ses.Respond(mpcm)
	ses.Interactive = false
}

func NewSenderLinSession(mpcn *MPCNode, sessionID string) *Session {
	ses := new(Session)
	ses.ID = sessionID
	ses.Protocol = Lin
	ses.HandleMessage = HandleLinMessage
	ses.Details = LinDetails //PrintLinState
	ses.Interactive = true
	st := NewLinState()
	st.Role = "sender"
	ses.State = st
	ses.Status = "awaiting peer"
	ses.ID = sessionID
	mpcn.sessions[ses.ID] = ses
	ses.Node = mpcn
	return ses
}

func NewRecLinSession(mpcn *MPCNode, sessionID string) *Session {
	ses := NewSenderLinSession(mpcn, sessionID)
	st := (ses.State).(*LinState)
	st.Role = "receiver"
	return ses
}

func LinPromptJoin(ses *Session) {
	lin := ses.State.(*LinState)
	items := []string{"Yes", "No", up}
	pr := promptui.Select{Label: "Accept Lindell invitation",
		Items: items,
	}
	_, res, _ := pr.Run()
	switch res {
	case up:
		return
	case "No":
		delete(ses.Node.sessions, ses.ID)
	case "Yes":
		lin.ShareA = PromptForNumber("ECDSA private key share", "97")

		Xs_x, Xs_y := CurveLindell.ScalarBaseMult(lin.ShareA.Bytes())
		lin.PubShareA = &ECPoint{Xs_x, Xs_y}

		lin.PubEcdsa = new(ecdsa.PublicKey)
		lin.PubEcdsa.Curve = CurveLindell
		lin.PubEcdsa.X, lin.PubEcdsa.Y = CurveLindell.Add(lin.PubShareA.X, lin.PubShareA.Y, lin.PubShareB.X, lin.PubShareB.Y)

		mpcm := new(MPCMessage)
		msg := &LinKeyGenEndMessage{lin.PubShareA, lin.PubEcdsa}
		tmp, _ := json.Marshal(msg)
		mpcm.Message = string(tmp)
		mpcm.Command = "keygen_end"
		mpcm.Protocol = Lin
		ses.Respond(mpcm)
		ses.Interactive = false
		ses.Status = "joined"
	}
}

func LinKeyGenEnd(ses *Session) {
	lin := ses.State.(*LinState)
	lin.PubEcdsa.Curve = CurveLindell
	pubX, pubY := CurveLindell.Add(lin.PubShareA.X, lin.PubShareA.Y, lin.PubShareB.X, lin.PubShareB.Y)
	mpcm := new(MPCMessage)
	if pubX.Cmp(lin.PubEcdsa.X) != 0 || pubY.Cmp(lin.PubEcdsa.Y) != 0 {
		fmt.Println("wrong ecdsa public key")
		mpcm.Message = "ko"
	} else {
		fmt.Println("successfully computed ecdsa public key")
		mpcm.Message = "ok"
	}
	mpcm.Command = "keygen_confirm"
	mpcm.Protocol = Lin
	ses.Respond(mpcm)
	ses.Interactive = false
	ses.Status = "keygen_end"
}

func LinPreSign(ses *Session) {
	fmt.Println("success")

	lin := ses.State.(*LinState)
	lin.Message = "test"
	lin.PartialNonceA = PromptForNumber("Partial nonce", "2") //rand.Int(rand.Reader, big.NewInt(1000))
	lin.PubPartialNonceA = new(ECPoint)
	lin.PubPartialNonceA.X, lin.PubPartialNonceA.Y = CurveLindell.ScalarBaseMult(lin.PartialNonceA.Bytes())

	msg := &LinPreSignMessage{lin.PubPartialNonceA, lin.Message}

	mpcm := new(MPCMessage)
	tmp, _ := json.Marshal(msg)
	mpcm.Message = string(tmp)
	mpcm.Command = "presign"
	ses.Respond(mpcm)
	ses.Interactive = false
	ses.Status = "sent partial nonce"
}

func LinPreSignB(ses *Session) {
	lin := ses.State.(*LinState)
	lin.PartialNonceB, _ = rand.Int(rand.Reader, big.NewInt(1000))
	lin.PubPartialNonceB = new(ECPoint)
	lin.PubPartialNonceB.X, lin.PubPartialNonceB.Y = CurveLindell.ScalarBaseMult(lin.PartialNonceB.Bytes())
	lin.PubNonce = new(ECPoint)
	lin.PubNonce.X, lin.PubNonce.Y = CurveLindell.Add(lin.PubPartialNonceB.X, lin.PubPartialNonceB.Y, lin.PubPartialNonceA.X, lin.PubPartialNonceA.Y)

	msg := &LinPreSignMessage{lin.PubPartialNonceB, lin.Message} // No need to send Message

	mpcm := new(MPCMessage)
	tmp, _ := json.Marshal(msg)
	mpcm.Message = string(tmp)
	mpcm.Command = "end_presign"
	ses.Respond(mpcm)
	ses.Interactive = false
	ses.Status = "sent partial nonce"
}

func LinPreSignEnd(ses *Session) {
	lin := ses.State.(*LinState)
	lin.PubNonce = new(ECPoint)
	lin.PubNonce.X, lin.PubNonce.Y = CurveLindell.Add(lin.PubPartialNonceB.X, lin.PubPartialNonceB.Y, lin.PubPartialNonceA.X, lin.PubPartialNonceA.Y)
	ses.Status = "finished presign"
}

func LinSign(ses *Session) {
	fmt.Println("sign")
}

func HandleLinMessage(mpcm *MPCMessage, ses *Session) {
	switch mpcm.Command {
	case "keygen_join":
		ses.Interactive = true
		msg := new(LinKeyGenMessage)
		json.Unmarshal([]byte(mpcm.Message), msg)
		st := (ses.State).(*LinState)
		st.Pub = msg.Pub
		st.PubShareB = msg.PubShare
		st.EncShareB = msg.EncShare
		ses.NextPrompt = LinPromptJoin

	case "keygen_end":
		msg := new(LinKeyGenEndMessage)
		json.Unmarshal([]byte(mpcm.Message), msg)
		st := (ses.State).(*LinState)
		st.PubEcdsa = msg.PubEcdsa
		st.PubShareA = msg.PubShare
		LinKeyGenEnd(ses)

	case "keygen_confirm":
		fmt.Println("comparison")
		if mpcm.Message == "ok" {
			fmt.Println("keygen_confirm ok")
			ses.Interactive = true
			ses.NextPrompt = LinPreSign
		} else {
			fmt.Println("failed keygen from", mpcm.SenderID)
		}

	case "presign":
		msg := new(LinPreSignMessage)
		json.Unmarshal([]byte(mpcm.Message), msg)
		st := (ses.State).(*LinState)
		st.Message = msg.Message
		st.PubPartialNonceA = msg.PubPartialNonce
		ses.Interactive = false
		LinPreSignB(ses)

	case "end_presign":
		msg := new(LinPreSignMessage)
		json.Unmarshal([]byte(mpcm.Message), msg)
		st := (ses.State).(*LinState)
		st.PubPartialNonceB = msg.PubPartialNonce
		ses.Interactive = false
		LinPreSignEnd(ses)

	case "sign":
		fmt.Println("sign")

	default:
		fmt.Println(mpcm.Command)
		return
	}
}
