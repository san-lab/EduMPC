//go:build sepior
// +build sepior

package sepior

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/manifoldco/promptui"
	"github.com/san-lab/EduMPC/edumpc"
)

const ProtName = edumpc.Protocol("sepior")

var SessionHandler = edumpc.SessionHandler{InitNewSepSessionUI, NewSepiorSession, Save, Load}

func Save(ses *edumpc.Session) ([]byte, error) { return nil, nil }
func Load(ses *edumpc.Session, b []byte) error { return nil }

func Init(mpcn *edumpc.MPCNode) {
	edumpc.AddPackageUI(sepiorui, RootUI)
	lmpcn = mpcn
	initSepNodes(networks[0][1])

	edumpc.Protocols[ProtName] = &SessionHandler
	edumpc.Protocols[PartSigProtocol] = PartSigHandler
	edumpc.Protocols[GenPresig] = presigHandler
}

func NewSepiorSession(mpcn *edumpc.MPCNode, sessionID string) *edumpc.Session {
	ses := new(edumpc.Session)
	ses.ID = sessionID
	ses.Protocol = ProtName
	ses.HandleMessage = HandleSepMessage
	ses.Details = ShowDetails
	ses.Interactive = true
	ses.ID = sessionID
	mpcn.NewLocalSession(ses.ID, ses)
	ses.Node = mpcn
	return ses
}

const GenKeyCmd = "GenerateKey"
const AddMetoKeyGen = "AddToKeyGen"
const JoinPartialSig = "JoinPartSig"
const AddMeToPartialSig = "AddToPartSig"
const DoPartialSig = "DoPartialSignig"
const ReassembleECDSASig = "ReassembleECDSASignature"

func HandleSepMessage(mpcm *edumpc.MPCMessage, ses *edumpc.Session) {
	switch mpcm.Command {
	case GenKeyCmd:
		ses.Interactive = true
		//A risk of an overwrite to be assessed
		sesState := new(KeyGenState)
		ses.State = ses.State
		sepmsg := new(KeyGenMsg)
		err := json.Unmarshal([]byte(mpcm.Message), sepmsg)
		if err != nil {
			fmt.Println(err)
			return
		}
		sesState.SepSessionID = sepmsg.SessionID
		ses.NextPrompt = AskToJoinKeyGeneration
		ses.State = new(KeyGenState) //This assumes GenKeyCmd is called exactly once
	case AddMetoKeyGen:
		sesState := ses.State.(*KeyGenState)
		sesState.ResponsesFrom = append(sesState.ResponsesFrom, mpcm.SenderID)
	case AddMeToPartialSig:

		coord, ok := CoordChannels[ses.ID]
		if ok {
			psmsg := new(ECDSAPartialSignMessage)
			err := json.Unmarshal([]byte(mpcm.Message), psmsg)
			if err != nil {
				fmt.Println("Parsing error:", err)
				return
			}
			for _, s := range psmsg.NodesAvailable {
				coord <- []string{s, mpcm.SenderID}
			}

		} else {
			fmt.Println("No coordination channel for ", ses.ID)
		}

	case JoinPartialSig:
		JoinECDSAPartialSigning(mpcm, ses)
	case DoPartialSig:
		go FullfillPartialSig(mpcm, ses)

	case ReassembleECDSASig:
		coord, ok := CoordChannels[ses.ID]
		if ok {
			psmsg := new(ECDSAPartialSignMessage)
			err := mpcm.CastMessage(psmsg)
			if err != nil {
				fmt.Println("Parsing error:", err)
				return
			}
			coord <- []string{hex.EncodeToString(psmsg.SignatureDER)}

		} else {
			fmt.Println("No coordination channel for ", ses.ID)
		}
	}
}

var CoordChannels = map[string]chan []string{}

const GenKey = "Generate key"
const SignMsg = "Sign message"
const SignPart = "Sign partially message"
const SignWithPresig = "Sign with pre-signature"
const GenPresigStr = "Generate pre-signatures"

func InitNewSepSessionUI(mpcn *edumpc.MPCNode) {
	pr := promptui.Select{Label: "Sepior actions:"}
	pr.Items = []string{GenKey, SignMsg, SignPart, SignWithPresig, GenPresigStr, up}
	pr.Size = 6
	for {
		_, res, _ := pr.Run()
		switch res {
		case up:
			return
		case GenKey:
			TriggerKeyGeneration(mpcn)
		case SignMsg:
			TriggerSigningPrompt(mpcn)
		case SignPart:
			TriggerPartialSigningPrompt(mpcn)
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

func Log(in ...interface{}) {
	fmt.Fprintln(os.Stdout, in...)
}

func Lerror(in ...interface{}) {
	s := fmt.Sprint(in...)
	s = promptui.Styler(promptui.FGRed)(s)
	Log(s)

}
