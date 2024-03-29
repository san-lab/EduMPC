//go:build sepior
// +build sepior

package sepior

import (
	"github.com/manifoldco/promptui"
	"github.com/san-lab/EduMPC/edumpc"
)

const sepiorui = "Sepior SDK"
const up = "Up"
const user = "Current credentials"

// clients
const TSMClient = "Sepior Nodes connected"
const ECDSAClient = "ECDSA"
const EdDSAClient = "EdDSA"
const UserClient = "Users"
const KeyClient = "Keys"

const keys = "Lisk keys"

func RootUI(mpcn *edumpc.MPCNode) {

	items := []string{TSMClient, ECDSAClient, EdDSAClient, UserClient, KeyClient}

	items = append(items, up)
	pr := promptui.Select{Label: "Sepior SDK",
		Items: items,
	}
	for {
		pr.Size = len(items)
		_, sid, _ := pr.Run()
		switch sid {
		case TSMClient:
			tsmClient()
		case ECDSAClient:
			ecdsaui(mpcn)
		case EdDSAClient:
		case UserClient:
			Users(mpcn)
		case KeyClient:
			KeysUI()
		case up:
			return

		}
	}

}
