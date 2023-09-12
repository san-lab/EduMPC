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

// Color according to variable set or not set. Also trims the string
func Colorize(message, color string) string {
	switch color {
	case "red":
		message = promptui.Styler(promptui.FGRed)(message)
	case "green":
		message = promptui.Styler(promptui.FGGreen)(message)
	case "magenta":
		message = promptui.Styler(promptui.FGMagenta)(message)
	default:
	}
	return message
}

func Trim(message string, length int) string {
	if len(message) > length {
		return fmt.Sprintf("%s...", message[0:length])
	}
	return message

}

func ColorAndTrim(message string, length int, values ...string) string {
	color := "green"
	if values[0] == "" || values[0] == "false" || values[0] == "<nil>" {
		color = "red"
	}
	coloredMessage := Colorize(message, color)
	trimmedValues := ""
	for _, v := range values {
		if trimmedValues == "" {
			trimmedValues = Trim(v, length)
		} else {
			trimmedValues = fmt.Sprintf("%s, %s", trimmedValues, Trim(v, length))
		}

	}
	return fmt.Sprintf("%s: %s", coloredMessage, trimmedValues)
}

func formatBits(reversedIterations []bool) string {
	result := ""
	for i := len(reversedIterations) - 1; i >= 0; i-- {
		if reversedIterations[i] {
			result = result + "0"
		} else {
			result = result + "1"
		}
	}
	return result
}

func PrintLinState(ses *Session) {
	// Dont print the whole numbers, just the beginning
	length := 40

	fmt.Println("Printing state...")
	st := (ses.State).(*LinState)
	fmt.Println("Role:", st.Role)

	fmt.Println("----------")
	fmt.Println(ColorAndTrim("Private key", length, fmt.Sprintf("%v", st.Priv != nil)))
	fmt.Println(ColorAndTrim("Pub N", length, st.Pub.N.String()))
	if st.PubEcdsa == nil {
		fmt.Println(ColorAndTrim("PubEcdsa", length, "<nil>"))
	} else {
		fmt.Println(ColorAndTrim("PubEcdsa", length, st.PubEcdsa.X.String(), st.PubEcdsa.Y.String()))
	}

	fmt.Println(ColorAndTrim("Secret share A", length, st.ShareA.String()))
	fmt.Println(ColorAndTrim("Secret share B", length, st.ShareB.String()))
	fmt.Println(ColorAndTrim("EncShareB", length, st.EncShareB.String()))

	if st.PubShareA == nil {
		fmt.Println(ColorAndTrim("PubShareA", length, "<nil>"))
	} else {
		fmt.Println(ColorAndTrim("PubShareA", length, st.PubShareA.X.String(), st.PubShareA.Y.String()))
	}

	if st.PubShareB == nil {
		fmt.Println(ColorAndTrim("PubShareB", length, "<nil>"))
	} else {
		fmt.Println(ColorAndTrim("PubShareB", length, st.PubShareB.X.String(), st.PubShareB.Y.String()))
	}

	fmt.Println("----------")
	fmt.Println(ColorAndTrim("Message", length, st.Message))
	fmt.Println(ColorAndTrim("PartialNonceA", length, st.PartialNonceA.String()))
	fmt.Println(ColorAndTrim("PartialNonceB", length, st.PartialNonceB.String()))

	if st.PubNonce == nil {
		fmt.Println(ColorAndTrim("PubNonce", length, "<nil>"))
	} else {
		fmt.Println(ColorAndTrim("PubNonce", length, st.PubNonce.X.String(), st.PubNonce.Y.String()))
	}

	if st.PubPartialNonceA == nil {
		fmt.Println(ColorAndTrim("PubPartialNonceA", length, "<nil>"))
	} else {
		fmt.Println(ColorAndTrim("PubPartialNonceA", length, st.PubPartialNonceA.X.String(), st.PubPartialNonceA.Y.String()))
	}

	if st.PubPartialNonceB == nil {
		fmt.Println(ColorAndTrim("PubPartialNonceB", length, "<nil>"))
	} else {
		fmt.Println(ColorAndTrim("PubPartialNonceB", length, st.PubPartialNonceB.X.String(), st.PubPartialNonceB.Y.String()))
	}

	fmt.Println("----------")
	fmt.Println(ColorAndTrim("D", length, st.D.String()))
	fmt.Println(ColorAndTrim("S", length, st.S.String()))

	if st.Role == "receiver" {
		fmt.Println("----------")
		fmt.Println("Attack:", st.Attack)
		fmt.Println("Verifies iteration?:", st.Bits)
		fmt.Println("Guessed bits so far:", Colorize(formatBits(st.Bits), "magenta"))
		fmt.Println("Guesse number so far (Y_b):", Colorize(st.Y_b.String(), "magenta"))
		fmt.Println("Iteration (L):", st.L)

	}
}

func LinDetails(ses *Session) {
	PrintLinState(ses)
	fmt.Println("----------")
	fmt.Println(promptui.Styler(promptui.FGBold)("Status:"), ses.Status) // TODO improve readability here
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
	ses.HandleMessage = HandleLinMessageB
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
	ses.HandleMessage = HandleLinMessageA
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
	} else {
		ses.Inactive = true
	}
}

func HandleLinMessageA(mpcm *MPCMessage, ses *Session) {
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

	case "keygen_confirm_A":
		if mpcm.Message == "ok" {
			fmt.Println("keygen_confirm ok")
			ses.Interactive = true
			ses.NextPrompt = LinPreSignA
		} else {
			fmt.Println("failed keygen from", mpcm.SenderID)
		}

	case "presign_end_A":
		msg := new(LinPreSignMessage)
		json.Unmarshal([]byte(mpcm.Message), msg)
		st := (ses.State).(*LinState)
		st.PubPartialNonceB = msg.PubPartialNonce
		ses.Interactive = false
		LinPreSignEndA(ses)

		ses.Interactive = true
		ses.NextPrompt = LinSignA

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
		fmt.Println("shouldnt be here... Command:", mpcm.Command)
		return
	}
}

func HandleLinMessageB(mpcm *MPCMessage, ses *Session) {
	switch mpcm.Command {

	case "keygen_end_B":
		msg := new(LinKeyGenEndMessage)
		json.Unmarshal([]byte(mpcm.Message), msg)
		st := (ses.State).(*LinState)
		st.PubEcdsa = msg.PubEcdsa
		st.PubShareA = msg.PubShare
		LinKeyGenEndB(ses)

	case "presign_B":
		msg := new(LinPreSignMessage)
		json.Unmarshal([]byte(mpcm.Message), msg)
		st := (ses.State).(*LinState)
		st.Message = msg.Message
		st.PubPartialNonceA = msg.PubPartialNonce
		ses.Interactive = false
		LinPreSignB(ses)

	case "sign_end_B":
		D := new(big.Int)
		json.Unmarshal([]byte(mpcm.Message), D)
		st := (ses.State).(*LinState)
		st.D = D
		ses.Interactive = false
		LinSignB(ses)

	default:
		fmt.Println("shouldnt be here... Command:", mpcm.Command)
		return
	}
}

/*
func HandleLinMessageA(mpcm *MPCMessage, ses *Session) {
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
*/
