package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/san-lab/EduMPC/chat"
	"github.com/san-lab/EduMPC/edumpc"
	"github.com/san-lab/EduMPC/guessgame"
	"github.com/san-lab/EduMPC/ot"
	"github.com/san-lab/EduMPC/plumbing"
	"github.com/san-lab/EduMPC/sepior"
)

func main() {
	// parse some flags

	roomFlag := flag.String("mpcnet", "DEFMPCNET", "name of the topic for the network")
	flag.Parse()
	edumpc.MPCNET = *roomFlag

	mpcn, err := plumbing.GetMPCNode()

	if err != nil {
		panic(err)
	}
	time.Sleep(time.Second)
	fmt.Println("Peer count:", mpcn.PeerCount())

	//let packages do the self-registration
	sepior.Init(mpcn)
	guessgame.Init(mpcn)
	ot.Init(mpcn)
	chat.Init(mpcn)

	//Init UI
	edumpc.TopUI(mpcn)

}
