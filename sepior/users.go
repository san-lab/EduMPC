package sepior

import (
	"encoding/json"

	"github.com/manifoldco/promptui"
	"github.com/san-lab/EduMPC/edumpc"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

const ListUsersLab = "List Users"

func Users(mpcn *edumpc.MPCNode) {
	uc := tsm.NewUsersClient(tsmC)
	//uc.ListUsers()

	items := []string{ListUsersLab, up}
	sel := promptui.Select{Label: "Users Management"}
	sel.Items = items
	sel.Size = len(items) + 1
	_, res, _ := sel.Run()
	switch res {
	case up:
		return
	case ListUsersLab:
		ListUsers(uc)
		return
	}

}

type userdisp struct {
	Name     string
	Dispname string
	Role     string
	AuthType string
}

const userTemplate = `---------- User {{.UserID}} ----------
{{ "Name:" | faint }}                  {{.DisplayName }}
{{ "Role:" | faint }}                  {{.Role }}
{{ "Authentication:" | faint }}	{{.AuthenticationType }}
{{ "Disabled:" | faint}}              {{.Disabled}}`

func ListUsers(uc tsm.UsersClient) {

	ul, err := uc.ListUsers()
	if err != nil {
		Lerror(err)
		return
	}
	/*
		UserID             string `json:"user_id"`
		Role               string `json:"role"`
		DisplayName        string `json:"display_name"`
		Description        string `json:"description"`
		AuthenticationType string `json:"authentication_type"`
		Disabled           bool   `json:"disabled"`
	*/

	up := struct {
		UserID string
		Up     bool
	}{"Up", true}
	items := []interface{}{}
	for _, u := range ul {
		items = append(items, u)

	}
	items = append(items, up)
	sel := promptui.Select{Label: "Existing users"}
	sel.Items = items
	sel.Size = len(items)
	exitPoint := len(items) - 1
	templates := &promptui.SelectTemplates{

		Active:   "{{.UserID | cyan}} ",
		Inactive: "{{.UserID}} ",
		Selected: "{{.UserID}}",
		Details: `{{if eq .UserID "Up"}}
exit {{else}}` + userTemplate + `{{end}}`,
	}
	sel.Templates = templates
	idx, _, err := sel.Run()
	if err != nil {
		Lerror(err)
		return
	}
	if idx == exitPoint {
		return
	} else {
		user, ok := items[idx].(tsm.User)
		if !ok {
			Lerror("Error casting")
			return
		}
		UserMng(user, uc)
	}

}

func UserMng(user tsm.User, uc tsm.UsersClient) {
	sel := promptui.Select{}
	sel.Label = user
	sel.Templates = &promptui.SelectTemplates{Label: `{{"---User: " | faint}} {{.UserID}}  {{"Disabled:" | faint}} {{.Disabled}} {{"---"| faint}}`}
	items := []interface{}{up}
	if user.Disabled {
		items = append(items, "Enable")
	} else {
		items = append(items, "Disable")
	}
	items = append(items, "Reset password")

	sel.Items = items
	_, res, _ := sel.Run()
	switch res {
	case "Enable":
		uc.Enable(user.UserID)
	case "Disable":
		uc.Disable(user.UserID)
	case "Reset password":
		creds, err := uc.ResetPassword(user.UserID)
		if err != nil {
			Lerror(err)
		}
		j, err := json.MarshalIndent(creds, " ", " ")
		if err != nil {
			Lerror(err)
		}
		Log(string(j))
	default:
		Log("Missed it...")
	}
	//uc.Disable(uID)
	//uc.Enable(uID)
	//uc.ResetPassword(uid)

}
