package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/san-lab/EduMPC/edumpc"
	"github.com/san-lab/EduMPC/guessgame"
	"github.com/san-lab/EduMPC/plumbing"
	"github.com/san-lab/EduMPC/sepior"
)

func main() {
	// parse some flags

	roomFlag := flag.String("mpcnet", "DEFMPCNET", "name of chat room to join")
	flag.Parse()
	edumpc.MPCNET = *roomFlag

	mpcn, err := plumbing.GetMPCNode()

	if err != nil {
		panic(err)
	}
	time.Sleep(time.Second)
	fmt.Println("Peer count:", mpcn.PeerCount())
	sepior.Init(mpcn)

	guessgame.A()
	edumpc.TopUI(mpcn)

}
