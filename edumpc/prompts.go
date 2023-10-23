package edumpc

import (
	"fmt"
	"sort"

	//	"strconv"
	"math/big"

	"github.com/manifoldco/promptui"
)

const up = "Up"
const config = "Config"
const peers = "Peers"
const useraction = "User action"
const details = "Details"
const history = "History"
const news = "New"

var packageUI = map[string]func(*MPCNode){}

func AddPackageUI(key string, ui func(*MPCNode)) {
	packageUI[key] = ui
	fmt.Println(key, "added")
}

func TopUI(mpcn *MPCNode) {
	for {
		items := []string{config, peers, "Sessions"}
		for k := range packageUI {
			items = append(items, k)
		}
		items = append(items, "EXIT")
		prompt := promptui.Select{
			Label: "MPC Node",
			Items: items,
		}
		_, it, _ := prompt.Run()

		switch it {
		case config:
			ConfigUI(mpcn)
		case peers:
			prs := mpcn.topic.ListPeers()
			if len(prs) > 0 {
				for _, pr := range prs {
					fmt.Println(pr)
				}
			} else {
				fmt.Println("No peers in the topic")
			}
		case "Sessions":
			SessionSelectUI(mpcn)
		case "EXIT":
			return
		default:
			if f, ok := packageUI[it]; ok {
				f(mpcn)
			}
		}

	}
}

func ConfigUI(mpcn *MPCNode) {
	fmt.Println(mpcn.self)
	fmt.Println(mpcn.topic)

}

func SessionSelectUI(mpcn *MPCNode) {
	uncoloredItems := map[string]string{} // Need to keep the inactive sessions uncolored id
	for {
		items := []string{}
		for key, ses := range mpcn.sessions {
			if !ses.Inactive {
				items = append(items, key)
				uncoloredItems[key] = key
			} else {
				greyKey := promptui.Styler(promptui.FGFaint)(key)
				items = append(items, greyKey)
				uncoloredItems[greyKey] = key
			}
		}
		items = append(items, news)
		uncoloredItems[news] = news
		items = append(items, up)
		uncoloredItems[up] = up

		pr := promptui.Select{Label: "Current sessions",
			Items: items,
		}
		_, sid, _ := pr.Run()
		sid = uncoloredItems[sid]
		if sid == news {
			StartNewSessionUI(mpcn)
		}
		if sid == up {
			return
		}
		if ses, ok := mpcn.sessions[sid]; ok {
			SessionUI(mpcn, ses)
		}
	}

}

func SessionUI(mpcn *MPCNode, ses *Session) {
	for {
		items := []string{details, history}
		if ses.Interactive {
			items = append(items, useraction)
		}
		items = append(items, up)
		pr := promptui.Select{Label: fmt.Sprintf("%s %s", ses.Protocol, ses.ID),
			Items: items}
		_, res, _ := pr.Run()
		if res == up {
			return
		}
		if res == details {
			if ses.Details != nil {
				ses.Details(ses)
			} else {
				ShowDetails(ses)
			}
		}
		if res == useraction {
			ses.NextPrompt(ses)

		}
		if res == history {
			History(ses)
		}
	}
}

func History(ses *Session) {
	fmt.Println("SESSION HISTORY OF", ses.ID, "--------------")
	for k, m := range ses.History {
		cut := len(m.Message)
		if cut > 100 {
			cut = 8
		}
		fmt.Printf("%v. from: %s command: %s\n\t%s...\n", k+1, m.SenderID, m.Command, m.Message[:cut])
	}
	fmt.Println("--------------------------------------------")
}

func StartNewSessionUI(mpcn *MPCNode) {
	items := []string{}

	// Extract the keys from the map
	var keys []string
	for key := range Protocols {
		keys = append(keys, string(key))
	}
	// Sort the keys lexicographically
	sort.Strings(keys)

	for _, prot := range keys {
		if prot != string(dumb) {
			items = append(items, prot)
		}
	}

	items = append(items, up)
	pr := promptui.Select{
		Label: "New session",
		Items: items,
	}
	_, prot, _ := pr.Run()
	if prot == up {
		return
	}
	if sh, ok := Protocols[Protocol(prot)]; ok {
		sh.NewSessionUI(mpcn)
	}

}

func PromptForNumber(label, def string) *big.Int {
	pr := promptui.Prompt{Label: label, Default: def}
	v := new(big.Int)
	for {
		res, _ := pr.Run()
		_, ok := v.SetString(res, 10)
		if ok {
			return v
		}
		pr.Default = res
	}

}
