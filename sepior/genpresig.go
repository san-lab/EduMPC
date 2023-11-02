//go:build sepior
// +build sepior

package sepior

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/manifoldco/promptui"
	"github.com/san-lab/EduMPC/edumpc"
)

/*
steps in the flow:
orig -> intention, nodes -> resp
resp << approve?
resp -> joining, nodes  > orig
orig << quorum?
org -> genpresig, nodes -> resp
resp -> orig ?
*/

const CmdInvite = "Join pre-sig generation"
const CmdJoin = "Add me to pre-sig"
const CmdDecline = "Not joining pre-sig"
const CmdCancel = "Cancel pre-sig generation"
const CmdGenerate = "Generate pre-sig"
const CmdGenerateResult = "Pre-sig generation result"

const GenPresig = edumpc.Protocol("Generate pre-sig")

type GenPresigState struct{}

var presigHandler = &edumpc.SessionHandler{TrigerPresigUI, NewPresigSession, nil, nil}

func TrigerPresigUI(mpcn *edumpc.MPCNode) {
	pr := promptui.Prompt{Label: "Generate new pre-sigs (y/n)?"}
	pr.Default = "n"
	res, _ := pr.Run()
	if res == "y" {
		sesID := "GenPresig-" + uuid.NewString()
		ses := NewPresigSession(mpcn, sesID)
		presinvmess := new(PresigInviteMsg)
		presinvmess.MyNodes = GetActiveClients()
		ses.Respond2(CmdInvite, presinvmess)

	}

}

type PresigInviteMsg struct {
	MyNodes []string
}

func NewPresigSession(mpcn *edumpc.MPCNode, sessionID string) *edumpc.Session {
	ses := new(edumpc.Session)
	ses.ID = sessionID
	ses.Protocol = GenPresig
	ses.HandleMessage = HandlePresigMessage
	//ses.Details = ShowDetails
	ses.Interactive = true
	ses.ID = sessionID
	ses.State = new(GenPresigState)
	mpcn.NewLocalSession(ses.ID, ses)
	ses.Node = mpcn
	return ses

}

func HandlePresigMessage(mpcm *edumpc.MPCMessage, ses *edumpc.Session) {
	if ses.State == nil {
		Lerror("No State in session:", ses.ID)
		return
	}
	presigState, ok := ses.State.(*GenPresigState)
	if !ok {
		Lerror("Wrong State type!")
		return
	}
	switch mpcm.Command {
	case CmdInvite:
	case CmdJoin:
	case CmdDecline:
	default:
		Lerror("Not implemented")
	}
	fmt.Println(presigState)
}
