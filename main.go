package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/san-lab/EduMPC/chat"
	"github.com/san-lab/EduMPC/edumpc"
	"github.com/san-lab/EduMPC/frblkatt1"
	"github.com/san-lab/EduMPC/guessgame"
	"github.com/san-lab/EduMPC/lindellmta"
	"github.com/san-lab/EduMPC/ot"

	"github.com/san-lab/EduMPC/parityattack"
	"github.com/san-lab/EduMPC/plumbing"
	//"github.com/san-lab/EduMPC/sepior"
)

type protocol struct {
	enabled bool
	init    func(*edumpc.MPCNode)
}
type protmap map[string]*protocol

func (pm *protmap) String() string {
	s := ""
	for l, v := range *pm {
		s += fmt.Sprintf("%s:%v; ", l, v.enabled)
	}
	return s
}

func (pm *protmap) Set(prn string) error {
	pr, ok := (*pm)[prn]
	if !ok {
		return fmt.Errorf("Unknown protocol:", prn)
	}
	pr.enabled = !pr.enabled
	return nil
}

var protocols = protmap{}

func init() {

	//protocols["sepior"] = &protocol{false, sepior.Init}
	protocols["guessgame"] = &protocol{true, guessgame.Init}
	protocols["oblivtransfer"] = &protocol{false, ot.Init}
	protocols["chatroom"] = &protocol{false, chat.Init}
	protocols["parityattack"] = &protocol{false, parityattack.Init}
	protocols["lindellPQ2attack"] = &protocol{false, frblkatt1.Init}
	protocols["paillierM2A"] = &protocol{false, lindellmta.Init}

}

func main() {
	// parse some flags

	roomFlag := flag.String("mpcnet", "DEFMPCNET", "name of the topic for the network")
	flag.Var(&protocols, "enable", "protocol to enable")
	flag.Parse()

	edumpc.MPCNET = *roomFlag

	mpcn, err := plumbing.GetMPCNode()

	if err != nil {
		panic(err)
	}
	time.Sleep(time.Second)
	fmt.Println("Peer count:", mpcn.PeerCount())

	//let packages do the self-registration
	for _, v := range protocols {
		if v.enabled {
			v.init(mpcn)
		}
	}

	/*
		sepior.Init(mpcn)
		guessgame.Init(mpcn)
		ot.Init(mpcn)
		chat.Init(mpcn)
		parityattack.Init(mpcn)
		frblkatt1.Init(mpcn)
		li*/
	//Init UI
	edumpc.TopUI(mpcn)

}
