//go:build sepior
// +build sepior

package sepior

import (
	"encoding/json"
	"fmt"

	"github.com/manifoldco/promptui"
	"github.com/san-lab/EduMPC/edumpc"
)

const sepprotocol = edumpc.Protocol("sepior")

func init() {
	edumpc.Protocols[sepprotocol] = &edumpc.SessionHandler{InitNewSepSessionUI, NewSepiorSession}
}

func NewSepiorSession(mpcn *edumpc.MPCNode, sessionID string) *edumpc.Session {
	ses := new(edumpc.Session)
	ses.ID = sessionID
	ses.Protocol = sepprotocol
	ses.HandleMessage = HandleSepMessage
	ses.Details = ShowDetails
	ses.Interactive = true
	ses.ID = sessionID
	mpcn.NewLocalSession(ses.ID, ses)
	ses.Node = mpcn
	ses.State = new(KeyGenState)
	return ses
}

const GenKeyCmd = "GenerateKey"

func HandleSepMessage(mpcm *edumpc.MPCMessage, ses *edumpc.Session) {
	switch mpcm.Command {
	case GenKeyCmd:
		ses.Interactive = true
		//A risk of an overwrite to be assessed
		sesState := ses.State.(*KeyGenState)
		sepmsg := new(KeyGenMsg)
		err := json.Unmarshal(mpcm.Message, sepmsg)
		if err != nil {
			fmt.Println(err)
			return
		}
		sesState.SepSessionID = sepmsg.SessionID
		ses.NextPrompt = AskToJoinKeyGeneration
	case "Add":
		sesState := ses.State.(*KeyGenState)
		sesState.ResponsesFrom = append(sesState.ResponsesFrom, mpcm.SenderID)
	}
}

func InitNewSepSessionUI(mpcn *edumpc.MPCNode) {
	pr := promptui.Select{Label: "Sepior actions:"}
	pr.Items = []string{"Generate key", up}
	for {
		_, res, _ := pr.Run()
		switch res {
		case up:
			return
		case "Generate key":
			TriggerKeyGeneration(mpcn)
		}
	}
}

func ShowDetails(ses *edumpc.Session) {
	fmt.Println("Session", ses.ID)
	fmt.Println("Status:", ses.Status)
	switch ses.State.(type) {
	case *KeyGenState:
		sesState := ses.State.(*KeyGenState)
		fmt.Println("Stage:", sesState.Stage)
		fmt.Println("Responses:", sesState.ResponsesFrom)
		fmt.Println("SepSesID:", sesState.SepSessionID)
	}
	edumpc.ShowHistory(ses)
}
