package main

import (
	"fmt"
	"strconv"

	"github.com/manifoldco/promptui"
)

const up = "Up"
const config = "Config"
const peers = "Peers"
const useraction = "User action"
const details = "Details"
const news = "New"

func TopUI(mpcn *MPCNode) {
	for {
		prompt := promptui.Select{
			Label: "MPC Node",
			Items: []string{config, peers, "Sessions", "EXIT"},
		}
		_, it, _ := prompt.Run()
		switch it {
		case config:
			ConfigUI(mpcn)
		case peers:
			for _, pr := range mpcn.topic.ListPeers() {
				fmt.Println(pr)
			}
		case "Sessions":
			SessionSelectUI(mpcn)
		case "EXIT":
			return
		}

	}
}

func ConfigUI(mpcn *MPCNode) {
	fmt.Println(mpcn.self)
	fmt.Println(mpcn.topic)

}

func SessionSelectUI(mpcn *MPCNode) {
	items := []string{}
	for key, _ := range mpcn.sessions {
		items = append(items, key)
	}
	items = append(items, news)
	items = append(items, up)
	pr := promptui.Select{Label: "Current sessions",
		Items: items,
	}
	_, sid, _ := pr.Run()
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

func SessionUI(mpcn *MPCNode, ses *Session) {
	for {
		items := []string{details}
		if ses.Interactive {
			items = append(items, useraction)
		}
		items = append(items, up)
		pr := promptui.Select{Label: fmt.Sprintf("%s %s", ses.Type, ses.ID),
			Items: items}
		_, res, _ := pr.Run()
		if res == up {
			return
		}
		if res == details {
			ses.Details(ses)
		}
		if res == useraction {
			ses.NextPrompt(mpcn, ses)

		}
	}
}

func StartNewSessionUI(mpcn *MPCNode) {
	items := []string{}
	for _, prot := range Protocols {
		if prot != dumb {
			items = append(items, string(prot))
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
	if prot == string(chat) {
		InitNewChat(mpcn)
	}
	if prot == string(ot1) {
		InitNewOt1(mpcn)
	}
	if prot == string(PM2A) {
		InitNewPM2A(mpcn)
	}
}

func PromptForNumber(label, def string) int {
	pr := promptui.Prompt{Label: label, Default: def}

	for {
		res, _ := pr.Run()
		v, err := strconv.Atoi(res)
		if err == nil {
			return v
		}
		pr.Default = res
	}

}
