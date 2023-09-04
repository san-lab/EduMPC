package sepior

import (
	"encoding/json"
	"fmt"

	"github.com/manifoldco/promptui"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

const keycount = "Count keys"
const keylist = "List keys"
const selKey = "Select key"
const deleteKeys = "Delete keys"

// filters
var genericKey = tsm.Key{}
var edKey = tsm.Key{Algorithm: "EdDSA"}
var ecKey = tsm.Key{Algorithm: "ECDSA"}
var rsaKey = tsm.Key{Algorithm: "RSA"}

func KeysUI() {
	if len(tsmC.Nodes) == 0 {
		fmt.Println("No nodes active")
		return
	}
	kC := tsm.NewKeyClient(tsmC)
	for {
		actions := []string{keycount, keylist, selKey, deleteKeys, up}
		pr := promptui.Select{Label: "Sepior SDK functions", Items: actions}
		pr.Size = len(actions)
		_, res, _ := pr.Run()
		switch res {
		case up:
			return
		case keycount:
			c, e := kC.CountKeys(genericKey)
			if e != nil {
				fmt.Println(e)
			} else {
				fmt.Printf("There is %v keys \n", c)
			}

		case keylist:
			PrintKeyListUI()

		case selKey:
			id, key := SelectKey(genericKey)
			fmt.Println(id, "selected")
			if key != nil {
				ManageKey(key)
			}
		case deleteKeys:
			DeleteKeys()

		}
	}

	//kC.CountPresigsForKey(keyID)
	//kC.CountPresigsForKey(keyID)

}

func PrintKeyListUI() {
	if len(tsmC.Nodes) == 0 {
		fmt.Println("No nodes active")
		return
	}
	pr := promptui.Select{Label: "Which keys to show?"}
	pr.Items = []string{ecdsakeys, eddkeys, rsakeys, allkeys, up}
	_, res, _ := pr.Run()
	var filter tsm.Key
	switch res {
	case allkeys:
		filter = genericKey
	case ecdsakeys:
		filter = ecKey
	case eddkeys:
		filter = edKey
	case rsakeys:
		filter = rsaKey
	default:
		return
	}
	PrintKeyList(&filter)
}

const eddkeys = "EdDSA keys"
const ecdsakeys = "ECDSA keys"
const rsakeys = "RSA keys"
const allkeys = "All keys"

func DeleteKeys() {
	if len(tsmC.Nodes) == 0 {
		fmt.Println("No nodes active")
		return
	}
	pr := promptui.Select{Label: "Which keys to delete?"}
	pr.Items = []string{ecdsakeys, eddkeys, rsakeys, allkeys, up}
	_, res, _ := pr.Run()
	var filter tsm.Key
	switch res {
	case allkeys:
		filter = genericKey
	case ecdsakeys:
		filter = ecKey
	case eddkeys:
		filter = edKey
	case rsakeys:
		filter = rsaKey
	default:
		return
	}
	keyC := tsm.NewKeyClient(tsmC)
	keys, err := keyC.FindKeys(filter)
	if err != nil {
		fmt.Println("Error getting keys", err)
	}
	for _, key := range keys {
		yn := promptui.Prompt{Label: fmt.Sprintf("Delete key %s? (y/n)", key.KeyID), Default: "n"}
		res, _ := yn.Run()
		if res == "y" {
			fmt.Println("deleting key ", key.KeyID)
			err := keyC.Delete(key.KeyID)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
}

func PrintKeyList(filter *tsm.Key) {
	if len(tsmC.Nodes) == 0 {
		fmt.Println("No nodes active")
		return
	}
	kC := tsm.NewKeyClient(tsmC)
	keys, err := kC.FindKeys(*filter)
	if err != nil {
		fmt.Println("Error getting keys", err)
	}
	for _, key := range keys {
		fmt.Println(key.KeyID, key.Algorithm)
	}
}

func SelectKey(filter tsm.Key) (string, *tsm.Key) {
	if len(tsmC.Nodes) == 0 {
		fmt.Println("No nodes active")
		return "", nil
	}
	kC := tsm.NewKeyClient(tsmC)
	pr := promptui.Select{Label: "Select key"}
	kl, err := kC.FindKeys(filter)
	if err != nil {
		fmt.Println(err)
		return "", nil
	}
	items := make([]string, len(kl), len(kl))
	for i, k := range kl {
		items[i] = fmt.Sprintf("%s (%s)", k.KeyID, k.Algorithm)
	}
	pr.Items = items
	pr.Size = 10
	idx, _, _ := pr.Run()
	return kl[idx].KeyID, &(kl[idx])

}

const keyinfo = "Info"
const keydel = "Delete"
const keydelpresig = "Delete all pre-sig"
const keycountpresig = "Count pre-sig's"

func ManageKey(key *tsm.Key) {

	if len(tsmC.Nodes) == 0 {
		fmt.Println("No nodes active")
		return
	}
	kC := tsm.NewKeyClient(tsmC)
	pr := promptui.Select{Label: fmt.Sprintf("Select action for key %s (%s)", key.KeyID, key.Algorithm)}
	pr.Items = []string{keyinfo, keycountpresig, keydelpresig, keydel, up}
	for {
		_, act, _ := pr.Run()
		switch act {
		case keyinfo:
			fmt.Printf("%s\n", KeyToString(key))
		case keydel:
			kC.Delete(key.KeyID)
			return
		case keydelpresig:
			kC.DeletePresigs(key.KeyID)
		case keycountpresig:
			fmt.Println(kC.CountPresigsForKey(key.KeyID))
		case up:
			return
		}
	}

}

func KeyToString(key *tsm.Key) string {
	b, e := json.MarshalIndent(key, " ", " ")
	if e != nil {
		return fmt.Sprint(e)
	}
	return string(b)
}

func x() {
	kC := tsm.NewKeyClient(tsmC)
	tsm.KeyClient.Delete(kC, "")
	tsm.UsersClient.ResetPassword(tsm.UsersClient(kC), "")

}
