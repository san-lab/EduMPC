package guessgame

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/google/uuid"
	"github.com/san-lab/EduMPC/edumpc"
)

const Guess = edumpc.Protocol("Guess the Number game")
const newgame = "New game"
const joingame = "Invitation received"
const resolution = "Number guessed"

type GuessState struct {
	Challenge *big.Int
	Tries     int
}

var SessionHandler = edumpc.SessionHandler{GameInvite, GameAccept, Save, Load}

func Init(*edumpc.MPCNode) {
	edumpc.Protocols[Guess] = &SessionHandler
}

func Save(ses *edumpc.Session) ([]byte, error) { return nil, nil }
func Load(ses *edumpc.Session, b []byte) error { return nil }

func GameInvite(mpcn *edumpc.MPCNode) {
	fmt.Println("Starting a new game")
	sid := "guess-" + uuid.NewString()
	ses := new(edumpc.Session)
	ses.ID = sid
	ses.Protocol = Guess
	x := SetGuessPrompt(ses)
	mpcn.NewLocalSession(ses.ID, ses)
	ses.Node = mpcn
	mpcm := new(edumpc.MPCMessage)
	mpcm.Command = "guess"
	mpcm.Message = fmt.Sprint(x)
	mpcm.Protocol = Guess
	ses.HandleMessage = HandleGuessMessage
	ses.Respond(mpcm)
	ses.Status = newgame
	ses.Details = myDetails
}

func GameAccept(mpcn *edumpc.MPCNode, sessionID string) *edumpc.Session {
	fmt.Println("Invitation accepted")
	ses := new(edumpc.Session)
	ses.ID = sessionID
	ses.Protocol = Guess
	ses.Interactive = true
	ses.Status = joingame
	ses.Details = myDetails
	ses.NextPrompt = GuessPrompt
	ses.HandleMessage = HandleGuessMessage
	mpcn.NewLocalSession(ses.ID, ses)
	ses.Node = mpcn
	ses.State = new(GuessState)
	return ses

	//Create a new session with id and protocol "Guess"
	//Set interactive to true. Set NextPrompt to a new prompt for guessing the number (new method)
	//Execute the prompt. Compare the numbers, communicate the result
	//Create a message with the Guess message (payload)
	//session.respond with a message
}

func HandleGuessMessage(mpcm *edumpc.MPCMessage, ses *edumpc.Session) {
	switch mpcm.Command {
	case "guess":
		ses.Interactive = true
		ses.NextPrompt = GuessPrompt
		challenge, err := new(big.Int).SetString(mpcm.Message, 10)
		if err {
			fmt.Println("Error", err)
		}

		st := new(GuessState)
		st.Challenge = challenge
		ses.State = st

	case "success":
		//TODO: Verify the guess
		fmt.Println(mpcm.Message)
		ses.Status = resolution
		st := new(GuessState)
		err := json.Unmarshal([]byte(mpcm.Message), &st)
		if err != nil {
			fmt.Println("Error unmarshalling")
		}
		ses.State = st
		ses.Details = myDetails
		ses.Inactive = true
	}
}

func SetGuessPrompt(ses *edumpc.Session) *big.Int {

	s := new(GuessState)
	s.Challenge = edumpc.PromptForNumber("Give a number to guess", "")
	ses.State = s
	return s.Challenge
}

func GuessPrompt(ses *edumpc.Session) {
	st, ok := ses.State.(*GuessState)
	if !ok {
		fmt.Println("Error casting")
	}
	x := edumpc.PromptForNumber("Try your guess", "")
	result := x.Cmp(st.Challenge)
	st.Tries++
	switch result {
	case -1:
		fmt.Println("Too small")
	case 0:
		fmt.Printf("Congratulations! You guessed it in %v tries\n", st.Tries)
		mpcm := new(edumpc.MPCMessage)
		mpcm.Command = "success"
		//Send to the originator the number of tries
		b, err := json.Marshal(st)
		mpcm.Message = string(b)
		if err != nil {
			fmt.Println("Error marshalling")
		}
		//mpcm.Message = fmt.Sprintf("I have guessed your number in %v tries. The value is %v", st.tries, x)
		mpcm.Protocol = Guess
		ses.Respond(mpcm)
		ses.Status = resolution
		ses.Details = myDetails
		ses.Interactive = false
		ses.Inactive = true
	case 1:
		fmt.Println("Too big")
	}
}

func myDetails(ses *edumpc.Session) {
	fmt.Println("Session ID", ses.ID)
	fmt.Println("Protocol", ses.Protocol)
	//fmt.Printf("Status of the session:  challenge %v, number of tries %v\n", ses.Status.challenge, ses.Status.tries)
	st, ok := ses.State.(*GuessState)
	if !ok {
		fmt.Println("Error casting")
	}
	switch ses.Status {
	case newgame:
		fmt.Printf("New game started. Number to guess: %v\n", st.Challenge)
	case joingame:
		fmt.Println("Invitation received from", ses.History[0].SenderID)
		fmt.Printf("Current number of tries %v\n", st.Tries)
	case resolution:
		fmt.Printf("Game over! Number guessed: %v. Number of tries: %v \n", st.Challenge, st.Tries)

	default:
		fmt.Println("I don´t know where we are")
	}
}
