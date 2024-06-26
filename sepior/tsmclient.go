//go:build sepior
// +build sepior

package sepior

import (
	"fmt"
	"log"

	"github.com/manifoldco/promptui"
	"github.com/san-lab/EduMPC/edumpc"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

const localcred string = `
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

const marblecredentials string = `{
    "userID": "NL8ncKSY0xFx4EJq4TL1cOdej2qy",
    "urls": [
        "http://marble.uksouth.cloudapp.azure.com:8500",
        "http://marble.uksouth.cloudapp.azure.com:8501",
        "http://marble.uksouth.cloudapp.azure.com:8502"
    ],
    "passwords": [
		"Uk01NQ4k6dIf3whBR8H5dlUBob01SoF3nitA1rEFPDIw",
        "bDoKix1PBfWqWvsPc4vKMreTcktoD1xxgM5OnkicVpXZ",
  		 "DOTEqnSVlYjbBeR02ktfBfI4br6eGHb79yqlIJiWonSa"
    ]
}`

const marbleadmincredentials string = `{
    "userID": "admin",
    "urls": [
        "http://marble.uksouth.cloudapp.azure.com:8500",
        "http://marble.uksouth.cloudapp.azure.com:8501",
        "http://marble.uksouth.cloudapp.azure.com:8502"
    ],
    "passwords": [
        "pass",
        "pass",
        "pass"
    ]
}`

const garmcred = `{
	"userID": "zFG98baOywe9vI1KZy82gReTKg9r",
	"urls": [
		"http://marble.uksouth.cloudapp.azure.com:8507",
		"http://marble.uksouth.cloudapp.azure.com:8508",
		"http://marble.uksouth.cloudapp.azure.com:8509"
	],
	"passwords": [
		"sT9gduAWsiibb7CW8jp89mVzZLwoOwbFpxT3MnbARlqV",
		"bX38nNlH9Ud2vU208eWTH63QbBz4SfgvA5YSI7kPVeh4",
		"WeiZTb3shQia0gZOSfOye6R7JbuTkofkZwTefP1ACJVx"
	]
}`

const k9dmincredentials string = `{
    "userID": "admin",
    "urls": [
        "http://20.13.99.178:80",
        "http://20.23.72.177:80",
        "http://20.23.72.202:80"
    ],
    "passwords": [
        "pass",
        "pass",
        "pass"
    ]
}`

const k9usercred = `{
	"userID": "0RRMl8XwS1eds1AMgVNu9QgOrJzG",
	"urls": [
	 "http://20.13.99.178:80",
	 "http://20.23.72.177:80",
	 "http://20.23.72.202:80"
	],
	"passwords": [
	 "lZvs1niJRZvAY4l0Ea029F3yXSnxXWw1eTIsHlffoZ1y",
	 "O9YymqoEMJhuJV5R0TGMVKiuoVGlceU1lc5JndrScPGL",
	 "BMSf49w9VzPe2NZV7pJ3ee4xmcbVqGvbKTms3Ii14EJY"
	]
   }`

/*
	{
	  "userID": "wAAYPgHft9seVmIBA1sIdVkjYwLT",
	  "urls": [
	   "http://20.13.99.178:80",
	   "http://20.23.72.177:80",
	   "http://20.23.72.202:80"
	  ],
	  "passwords": [
	   "AOlVWie90yl2dqBeY0pVzf6AOyel3PmSZ6iYcW6t3MYH",
	   "z9XxxR5uzmlklV5h6SRc947EI8wi2JKifRb0i9qte3jz",
	   "jK0WT4alPVHQ7y85HUgcJ9EExZnjqU86vr6EIwUexAF2"
	  ]
	 }
*/
var networks = [][]string{{"Local", localcred}, {"Marble Vanilla", marblecredentials}, {"Marble Vanilla Admin", marbleadmincredentials}, {"Marble Gramin", garmcred}, {"K9 admin", k9dmincredentials}, {"K9 user", k9usercred}}

var lmpcn *edumpc.MPCNode

var creds tsm.PasswordCredentials
var currNodes = []*SwitchNode{} //node URL active/inactive

type SwitchNode struct {
	Node tsm.Node
	On   bool
}

var singleNodecreds []tsm.PasswordCredentials
var SingleNodeCilents = map[string]tsm.Client{}

func GetActiveClients() []string {
	urls := []string{}
	for _, n := range currNodes {
		if n.On {
			url := n.Node.URL()
			urls = append(urls, url.String())
		}
	}
	return urls
}

func initSepNodes(credentials string) {
	currNodes = []*SwitchNode{}
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
	setNodes()

	//Create single-node credentials
	for i := range creds.URLs {
		screds := tsm.PasswordCredentials{
			UserID:    creds.UserID,
			URLs:      []string{creds.URLs[i]},
			Passwords: []string{creds.Passwords[i]},
		}
		singleNodecreds = append(singleNodecreds, screds)
		client, err := tsm.NewPasswordClientFromCredentials(screds)
		if err != nil {
			log.Fatal(err)
		}
		SingleNodeCilents[creds.URLs[i]] = client

	}

}

var tsmC tsm.Client

const netchoice = "Change network"

// Not thread safe
func tsmClient() {
	defer setNodes()
	for {
		labels := []string{up}
		for _, snd := range currNodes {
			url := snd.Node.URL()
			labels = append(labels, fmt.Sprintf("%v %s %v", len(labels), url.String(), snd.On))
		}
		labels = append(labels, netchoice)

		pr := promptui.Select{Label: fmt.Sprintf("Toggle Node active/inactive [%v peers]", lmpcn.PeerCount()), Items: labels}
		idx, lab, _ := pr.Run()
		if lab == up {
			return
		}
		if lab == netchoice {
			selectNetwork()
			continue
		}
		toggleNode := currNodes[idx-1]
		toggleNode.On = !toggleNode.On
	}

}

func selectNetwork() {
	items := []string{up}
	for _, nt := range networks {
		items = append(items, nt[0])
	}
	spr := promptui.Select{Label: "Select BD/Sep network"}
	spr.Items = items
	i, res, _ := spr.Run()
	if res == up {
		return
	}
	creds := networks[i-1][1]
	initSepNodes(creds)
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
