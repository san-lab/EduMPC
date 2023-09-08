package guessgame

import (
	"fmt"
	"math/big"

	"github.com/google/uuid"
	"github.com/san-lab/EduMPC/edumpc"
)

const Guess = edumpc.Protocol("Guess the number game")

func init() {
	edumpc.Protocols[Guess] = &edumpc.SessionHandler{GameInvite, GameAccept}
	//fmt.Println(edumpc.Protocols)
}
func A() {}

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
}

func GameAccept(mpcn *edumpc.MPCNode, sessionID string) *edumpc.Session {
	fmt.Println("Invitation accepted")
	ses := new(edumpc.Session)
	ses.ID = sessionID
	ses.Protocol = Guess
	ses.Interactive = true
	ses.NextPrompt = GuessPrompt
	ses.HandleMessage = HandleGuessMessage
	mpcn.NewLocalSession(ses.ID, ses)
	ses.Node = mpcn
	ses.State = new(guessState)
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

		st := new(guessState)
		st.challenge = challenge
		ses.State = st

	case "success":
		fmt.Println(mpcm.Message)
	}
}

func SetGuessPrompt(ses *edumpc.Session) *big.Int {

	s := new(guessState)
	s.challenge = edumpc.PromptForNumber("Give a number to guess", "")
	ses.State = s
	return s.challenge
}

type guessState struct {
	challenge *big.Int
	tries     int
}

func GuessPrompt(ses *edumpc.Session) {
	st, ok := ses.State.(*guessState)
	if !ok {
		fmt.Println("Error casting")
	}
	x := edumpc.PromptForNumber("Try your guess", "")
	result := x.Cmp(st.challenge)
	st.tries++
	switch result {
	case -1:
		fmt.Println("Too small")
	case 0:
		fmt.Printf("Congratulations! You guessed it in %v tries\n", st.tries)
		mpcm := new(edumpc.MPCMessage)
		mpcm.Command = "success"
		mpcm.Message = fmt.Sprintf("I have guessed your number in %v tries. The value is %v", st.tries, x)
		mpcm.Protocol = Guess
		ses.Respond(mpcm)
		ses.Interactive = false
	case 1:
		fmt.Println("Too big")
	}
}
