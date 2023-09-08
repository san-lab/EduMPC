package edumpc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
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
	// Attack mode
	Attack bool
	Bits   []bool
	L      *big.Int
	Y_b    *big.Int
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

	fmt.Println("Attack:", st.Attack)
	fmt.Println("Bits / Verifies? (reversed list...):", st.Bits) // TODO improve visuals
	fmt.Println("L:", st.L)
	fmt.Println("Y_b:", st.Y_b)
}

func LinDetails(ses *Session) {
	PrintLinState(ses)
	fmt.Println(ses.History) // TODO remove history?
}

func InitNewLin(mpcn *MPCNode) {
	var err error
	sid := "Lin-" + uuid.NewString()
	ses := NewSenderLinSession(mpcn, sid)
	st := (ses.State).(*LinState)

	st.ShareB = PromptForNumber("ECDSA private key share", "33")

	b := PromptForNumber("Bits for paillier key", "1024")
	bits := int(b.Int64())
	st.Priv, st.Pub = GenerateNiceKeyPair(bits)

	st.EncShareB = st.Pub.Encrypt(st.ShareB)
	Xs_x, Xs_y := CurveLindell.ScalarBaseMult(st.ShareB.Bytes())
	st.PubShareB = &ECPoint{Xs_x, Xs_y}

	mpcm := new(MPCMessage)
	mpcm.Command = "keygen_join_A"
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

func LinPromptJoinA(ses *Session) {
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
		items := []string{"Yes", "No", up}
		pr := promptui.Select{Label: "Try to perform an attack?",
			Items: items,
		}
		_, att, _ := pr.Run()
		if att == "Yes" {
			lin.Attack = true
			lin.L = big.NewInt(1)
			lin.Y_b = big.NewInt(0)
		} else {
			lin.Attack = false
		}

		lin.ShareA = PromptForNumber("ECDSA private key share", "97")

		lin.PubEcdsa = new(ecdsa.PublicKey)
		lin.PubEcdsa.Curve = CurveLindell

		Xs_x, Xs_y := lin.PubEcdsa.Curve.ScalarBaseMult(lin.ShareA.Bytes())
		lin.PubShareA = &ECPoint{Xs_x, Xs_y}
		lin.PubEcdsa.X, lin.PubEcdsa.Y = lin.PubEcdsa.Curve.Add(lin.PubShareA.X, lin.PubShareA.Y, lin.PubShareB.X, lin.PubShareB.Y)

		mpcm := new(MPCMessage)
		msg := &LinKeyGenEndMessage{lin.PubShareA, lin.PubEcdsa}
		tmp, _ := json.Marshal(msg)
		mpcm.Message = string(tmp)
		mpcm.Command = "keygen_end_B"
		mpcm.Protocol = Lin
		ses.Respond(mpcm)
		ses.Interactive = false
		ses.Status = "A joined"
	}
}

func LinKeyGenEndB(ses *Session) {
	lin := ses.State.(*LinState)
	lin.PubEcdsa.Curve = CurveLindell
	pubX, pubY := lin.PubEcdsa.Curve.Add(lin.PubShareA.X, lin.PubShareA.Y, lin.PubShareB.X, lin.PubShareB.Y)
	mpcm := new(MPCMessage)
	if pubX.Cmp(lin.PubEcdsa.X) != 0 || pubY.Cmp(lin.PubEcdsa.Y) != 0 {
		fmt.Println("wrong ecdsa public key")
		mpcm.Message = "ko"
	} else {
		fmt.Println("successfully computed ecdsa public key")
		mpcm.Message = "ok"
	}
	mpcm.Command = "keygen_confirm_A"
	mpcm.Protocol = Lin
	ses.Respond(mpcm)
	ses.Interactive = false
	ses.Status = "keygen end"
}

func LinPreSignA(ses *Session) {
	lin := ses.State.(*LinState)
	//TODO Prompt for message?
	lin.Message = "test"

	suggestedPartialNonce, _ := rand.Int(rand.Reader, big.NewInt(1000))

	if lin.Attack {
		suggestedPartialNonce.Exp(big.NewInt(2), lin.L, nil)
		label := fmt.Sprintf("The partial nonce for iteration %s of the attack must be %s", lin.L.String(), suggestedPartialNonce.String())
		PromptForNumber(label, suggestedPartialNonce.String())
		lin.PartialNonceA = new(big.Int).Set(suggestedPartialNonce)
	} else {
		lin.PartialNonceA = PromptForNumber("Partial nonce", suggestedPartialNonce.String())
	}

	lin.PubPartialNonceA = new(ECPoint)
	lin.PubPartialNonceA.X, lin.PubPartialNonceA.Y = lin.PubEcdsa.Curve.ScalarBaseMult(lin.PartialNonceA.Bytes())

	msg := &LinPreSignMessage{lin.PubPartialNonceA, lin.Message}

	mpcm := new(MPCMessage)
	tmp, _ := json.Marshal(msg)
	mpcm.Message = string(tmp)
	mpcm.Command = "presign_B"
	ses.Respond(mpcm)
	ses.Interactive = false
	ses.Status = "A sent partial nonce"
}

func LinPreSignB(ses *Session) {
	lin := ses.State.(*LinState)
	lin.PartialNonceB, _ = rand.Int(rand.Reader, big.NewInt(1000))
	lin.PubPartialNonceB = new(ECPoint)
	lin.PubPartialNonceB.X, lin.PubPartialNonceB.Y = lin.PubEcdsa.Curve.ScalarBaseMult(lin.PartialNonceB.Bytes())
	lin.PubNonce = new(ECPoint)
	lin.PubNonce.X, lin.PubNonce.Y = lin.PubEcdsa.Curve.ScalarMult(lin.PubPartialNonceA.X, lin.PubPartialNonceA.Y, lin.PartialNonceB.Bytes())

	msg := &LinPreSignMessage{lin.PubPartialNonceB, lin.Message} // No need to send Message

	mpcm := new(MPCMessage)
	tmp, _ := json.Marshal(msg)
	mpcm.Message = string(tmp)
	mpcm.Command = "presign_end_A"
	ses.Respond(mpcm)
	ses.Interactive = false
	ses.Status = "B sent partial nonce"
}

func LinPreSignEndA(ses *Session) {
	lin := ses.State.(*LinState)
	lin.PubNonce = new(ECPoint)
	lin.PubNonce.X, lin.PubNonce.Y = lin.PubEcdsa.Curve.ScalarMult(lin.PubPartialNonceB.X, lin.PubPartialNonceB.Y, lin.PartialNonceA.Bytes())
	ses.Status = "finished presign"
}

func LinSignA(ses *Session) {
	lin := ses.State.(*LinState)

	m_hash := sha256.Sum256([]byte(lin.Message))
	m_hash_bigint := hashToInt(m_hash[:], lin.PubEcdsa.Curve)

	if !lin.Attack {
		lin.D = SignLindellPartyA(lin.ShareA, lin.PartialNonceA, lin.PubNonce.X, m_hash_bigint, lin.EncShareB, lin.Pub)
	} else {
		// User should not change these values...prompts are ignored by picking the values from the state
		label := fmt.Sprintf("The attack value for iteration %s must be l = %s", lin.L.String(), lin.L.String())
		PromptForNumber(label, lin.L.String())
		label = fmt.Sprintf("The attack value for iteration %s must be y_b = %s", lin.L.String(), lin.Y_b.String())
		PromptForNumber(label, lin.Y_b.String())
		lin.D = SignLindellAdversaryPartyA(lin.ShareA, lin.PartialNonceA, lin.PubNonce.X, m_hash_bigint, lin.EncShareB, lin.L, lin.Y_b, lin.Pub)
	}

	mpcm := new(MPCMessage)
	tmp, _ := json.Marshal(lin.D)
	mpcm.Message = string(tmp)
	mpcm.Command = "sign_end_B"
	ses.Respond(mpcm)
	ses.Interactive = false
	ses.Status = "A sent partial signature"
}

func LinSignB(ses *Session) {
	lin := ses.State.(*LinState)
	m_hash := sha256.Sum256([]byte(lin.Message))

	lin.S = SignLindellPartyB(lin.PartialNonceB, lin.D, lin.Priv)

	verifies := ecdsa.Verify(lin.PubEcdsa, m_hash[:], lin.PubNonce.X, lin.S)
	lin.Bits = append(lin.Bits, verifies)

	mpcm := new(MPCMessage)
	tmp, _ := json.Marshal(verifies)
	mpcm.Message = string(tmp)
	mpcm.Command = "finish_A"
	ses.Respond(mpcm)
	ses.Interactive = false
	ses.Status = "B verified final signature"
}

func FinishA(ses *Session) {
	lin := ses.State.(*LinState)
	fmt.Println("Signature:", lin.Bits[len(lin.Bits)-1])
	ses.Status = "finished protocol iteration"

	if lin.Attack {
		lin.L.Add(lin.L, big.NewInt(1))
		if !lin.Bits[len(lin.Bits)-1] {
			lin.Y_b.Add(lin.Y_b, new(big.Int).Div(lin.PartialNonceA, big.NewInt(2)))
		}
	}
}

func RepeatA(ses *Session) {
	lin := ses.State.(*LinState)

	items := []string{"Yes", "No", up}
	pr := promptui.Select{Label: "Start another signing round?",
		Items: items,
	}
	_, res, _ := pr.Run()
	if res == "Yes" {

		// State cleanup for better readeablity
		lin.Message = ""
		lin.PartialNonceA = nil
		lin.PartialNonceB = nil
		lin.PubNonce = nil
		lin.PubPartialNonceA = nil
		lin.PubPartialNonceB = nil
		lin.D = nil
		lin.S = nil

		ses.Interactive = true
		ses.NextPrompt = LinPreSignA
	}
}

func HandleLinMessage(mpcm *MPCMessage, ses *Session) {
	switch mpcm.Command {
	case "keygen_join_A":
		ses.Interactive = true
		msg := new(LinKeyGenMessage)
		json.Unmarshal([]byte(mpcm.Message), msg)
		st := (ses.State).(*LinState)
		st.Pub = msg.Pub
		st.PubShareB = msg.PubShare
		st.EncShareB = msg.EncShare
		ses.NextPrompt = LinPromptJoinA

	case "keygen_end_B":
		msg := new(LinKeyGenEndMessage)
		json.Unmarshal([]byte(mpcm.Message), msg)
		st := (ses.State).(*LinState)
		st.PubEcdsa = msg.PubEcdsa
		st.PubShareA = msg.PubShare
		LinKeyGenEndB(ses)

	case "keygen_confirm_A":
		if mpcm.Message == "ok" {
			fmt.Println("keygen_confirm ok")
			ses.Interactive = true
			ses.NextPrompt = LinPreSignA
		} else {
			fmt.Println("failed keygen from", mpcm.SenderID)
		}

	case "presign_B":
		msg := new(LinPreSignMessage)
		json.Unmarshal([]byte(mpcm.Message), msg)
		st := (ses.State).(*LinState)
		st.Message = msg.Message
		st.PubPartialNonceA = msg.PubPartialNonce
		ses.Interactive = false
		LinPreSignB(ses)

	case "presign_end_A":
		msg := new(LinPreSignMessage)
		json.Unmarshal([]byte(mpcm.Message), msg)
		st := (ses.State).(*LinState)
		st.PubPartialNonceB = msg.PubPartialNonce
		ses.Interactive = false
		LinPreSignEndA(ses)

		ses.Interactive = true
		ses.NextPrompt = LinSignA

	case "sign_end_B":
		D := new(big.Int)
		json.Unmarshal([]byte(mpcm.Message), D)
		st := (ses.State).(*LinState)
		st.D = D
		ses.Interactive = false
		LinSignB(ses)

	case "finish_A":
		verifies := new(bool)
		json.Unmarshal([]byte(mpcm.Message), verifies)
		st := (ses.State).(*LinState)
		st.Bits = append(st.Bits, *verifies) // true = 0, false = 1
		ses.Interactive = false
		FinishA(ses)

		ses.Interactive = true
		ses.NextPrompt = RepeatA

	default:
		fmt.Println(mpcm.Command)
		return
	}
}
