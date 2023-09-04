//go:build sepior
// +build sepior

package sepior

import (
	"fmt"

	"github.com/manifoldco/promptui"
	"github.com/san-lab/EduMPC/edumpc"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

const credentials string = `
{
	"userID": "J2ovPLhDEL1EJDedB41FVfBJwKKo",
	"passwords": [
	  "E1SOxGl0dFGKb5T8wEvAEd7sQuYQvuuHwf9bFBPWcZ28",
	  "UkTdu7tbmEtyPERLYDsBQHw18VcimpLqeOWtdy6biATv",
	  "0fHv9A2BbcXUWXj1aeH6nnRAgrfk54OYuRYfvnhGHT15"
	],
	"urls": [
	  "http://localhost:8502",
	  "http://localhost:8501",
	  "http://localhost:8500"
	]
  }
	`

var lmpcn *edumpc.MPCNode

func Init(mpcn *edumpc.MPCNode) {
	edumpc.AddPackageUI(sepiorui, RootUI)
	lmpcn = mpcn
	initSepNodes()
}

var creds tsm.PasswordCredentials
var currNodes = []*SwitchNode{} //node URL active/inactive

type SwitchNode struct {
	Node tsm.Node
	On   bool
}

func initSepNodes() {
	var err error
	creds, err = tsm.DecodePasswordCredentials(credentials)
	if err != nil {
		fmt.Println("1", err)
	}
	tsmC, err = tsm.NewPasswordClientFromCredentials(creds)
	if err != nil {
		fmt.Println("2", err)
	}
	for i, nd := range tsmC.Nodes {
		active := (i == lmpcn.PeerCount())
		currNodes = append(currNodes, &SwitchNode{nd, active})
	}

}

var tsmC tsm.Client

// Not thread safe
func tsmClient() {
	defer setNodes()
	for {
		labels := []string{up}
		for _, snd := range currNodes {
			url := snd.Node.URL()
			labels = append(labels, fmt.Sprintf("%v %s %v", len(labels), url.String(), snd.On))
		}

		pr := promptui.Select{Label: fmt.Sprintf("Toggle Node active/inactive [%v peers]", lmpcn.PeerCount()), Items: labels}
		idx, lab, _ := pr.Run()
		if lab == up {
			return
		}
		toggleNode := currNodes[idx-1]
		toggleNode.On = !toggleNode.On
	}

}

func setNodes() {
	nds := []tsm.Node{}
	for _, v := range currNodes {
		if v.On {
			nds = append(nds, v.Node)
		}
	}
	tsmC.Nodes = nds
}
