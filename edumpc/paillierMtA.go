package edumpc

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/google/uuid"
	"github.com/manifoldco/promptui"
)

type PM2AMessage struct {
	N *big.Int
	V *big.Int //Encrypted value
}

type PM2AState struct {
	Role     string
	Priv     *PaillierPriv
	Pub      *PaillierPub
	MulShare *big.Int
	AddShare *big.Int
	V        *big.Int
	V1       *big.Int
}

const initial = "awaiting peer"
const invited = "invitation received"
const joined = "joined"
const completed = "completed"
const confirmed = "confirmed"

func NewPM2AState() *PM2AState {
	st := new(PM2AState)
	st.MulShare = new(big.Int)
	st.AddShare = new(big.Int)
	return st
}

func PrintPM2AState(ses *Session) {
	fmt.Println("Printing state...")
	st := (ses.State).(*PM2AState)
	fmt.Println("Role:", st.Role)
	fmt.Println("Multiplicative secret:", st.MulShare)
	fmt.Println("Additive secret:", st.AddShare) //TODO an array of counterparties
	fmt.Println("Private key:", st.Priv != nil)
	n := big.NewInt(0)
	if st.Pub != nil {
		n = st.Pub.N
	}
	fmt.Println("N:", n)
	fmt.Println("V:", st.V)
	fmt.Println("V1:", st.V1)
}

func myDetails(ses *Session) {
	fmt.Println("First attempt")
	fmt.Println("Session ID", ses.ID)
	fmt.Println("Protocol", ses.Protocol)
	fmt.Printf("Status of the session is %s \n", ses.Status)
	sessionState := (ses.State).(*PM2AState)
	switch ses.Status {
	case initial:
		fmt.Println("This is the first step")
	case invited:
		fmt.Println("Invitation received from", ses.History[0].SenderID)
	case joined:
		fmt.Println("Invitation accepted. Local variables set")
		fmt.Println("Secret multiplicative share", sessionState.MulShare)
		fmt.Println("Secret additive share", sessionState.AddShare)

	case confirmed:
		fmt.Println("Invitation confirmed. Local variables set")
		fmt.Println("Secret multiplicative share", sessionState.MulShare)
		fmt.Println("Secret additive share", sessionState.AddShare)

	default:
		fmt.Println("I don´t know where we are")
	}
}

func InitNewPM2A(mpcn *MPCNode) {
	var err error
	sid := "pm2a-" + uuid.NewString()
	ses := NewSenderPM2ASession(mpcn, sid)
	st := (ses.State).(*PM2AState)

	st.MulShare = PromptForNumber("Local secret value", "")

	b := PromptForNumber("Bits for primes:", "1024")
	bits := int(b.Int64())
	st.Priv, st.Pub = GenerateNiceKeyPair(bits)

	mpcm := new(MPCMessage)
	mpcm.Command = "join"
	msg := &PM2AMessage{}
	msg.N = st.Priv.N
	msg.V = st.Pub.Encrypt(st.MulShare)
	st.V = msg.V
	bs, err := json.Marshal(msg)
	if err != nil {
		fmt.Println(err)
	}
	mpcm.Message = string(bs)

	mpcm.Protocol = PM2A
	ses.Respond(mpcm)

}

func NewRecPM2ASession(mpcn *MPCNode, sessionID string) *Session {
	ses := NewSenderPM2ASession(mpcn, sessionID)
	st := (ses.State).(*PM2AState)
	st.Role = "receiver"
	return ses
}

func NewSenderPM2ASession(mpcn *MPCNode, sessionID string) *Session {
	ses := new(Session)
	ses.ID = sessionID
	ses.Protocol = PM2A
	ses.HandleMessage = HandlePM2AMessage
	ses.Details = myDetails
	ses.Interactive = true
	ses.NextPrompt = PM2APrompt
	st := NewPM2AState()
	st.Role = "sender"
	ses.State = st
	ses.Status = "awaiting peer"
	ses.ID = sessionID
	mpcn.sessions[ses.ID] = ses
	ses.Node = mpcn
	return ses

}

func HandlePM2AMessage(mpcm *MPCMessage, ses *Session) {
	//st := (ses.State).(*PM2AState)
	switch mpcm.Command {
	case "join":
		ses.Interactive = true
		ses.NextPrompt = PM2APromptJoin

		msg := new(PM2AMessage)
		err := json.Unmarshal([]byte(mpcm.Message), msg)
		if err != nil {
			fmt.Println(err)
		}
		st := (ses.State).(*PM2AState)
		st.Pub = &PaillierPub{msg.N, new(big.Int).Mul(msg.N, msg.N)}
		st.V = msg.V
		ses.Status = "invitation received"

	case "save":
		ses.Interactive = false
		st := (ses.State).(*PM2AState)
		msg := new(PM2AMessage)
		err := json.Unmarshal([]byte(mpcm.Message), msg)
		if err != nil {
			fmt.Println(err)
		}
		st.V1 = msg.V
		st.AddShare = st.Priv.Decrypt(msg.V)
		fmt.Println(msg.N.Cmp(st.AddShare))
		ses.Status = "all completed"
		ses.Respond(&MPCMessage{Command: "OK"})

	case "OK":
		ses.Status = confirmed

	default:
		fmt.Println("we shouldnt be here...")

	}

}

func PM2APromptJoin(ses *Session) {
	//ots := ses.State.(*OT1State)
	items := []string{"Yes", "No", up}
	pr := promptui.Select{Label: "Accept PM2A invitation",
		Items: items,
	}
	_, res, _ := pr.Run()
	switch res {
	case up:
		return
	case "No":
		delete(ses.Node.sessions, ses.ID)
	case "Yes":

		v := PromptForNumber("Local multiplicative share", "")

		st := (ses.State).(*PM2AState)
		st.MulShare = v

		bf := PromptForNumber("Local aditive share", "")
		st.AddShare = bf //TODO randomize
		E := st.Pub.Encrypt(new(big.Int).Neg(st.AddShare))
		V1 := new(big.Int).Exp(st.V, st.MulShare, st.Pub.N2)
		V1.Mul(V1, E)
		V1.Mod(V1, st.Pub.N2)
		st.V1 = V1

		msg := new(PM2AMessage)
		msg.N = st.Pub.N
		msg.V = V1
		b, err := json.Marshal(msg)
		if err != nil {
			fmt.Println(err)
		}

		mpcm := new(MPCMessage)
		mpcm.Message = string(b)
		mpcm.Command = "save"

		ses.Respond(mpcm)
		ses.Interactive = false
		ses.Status = "joined"
	}
}

func HandleInitialMessage() {}

func PM2APrompt(ses *Session) {

}
