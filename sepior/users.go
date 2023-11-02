package sepior

import (
	"github.com/manifoldco/promptui"
	"github.com/san-lab/EduMPC/edumpc"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

const ListUsersLab = "List Users"

func Users(mpcn *edumpc.MPCNode) {
	uc := tsm.NewUsersClient(tsmC)
	//uc.ListUsers()
	//uc.Disable(uID)
	//uc.Enable(uID)
	//uc.ResetPassword(uid)
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
	}

}

type userdisp struct {
	Name     string
	Dispname string
	Role     string
	AuthType string
}

func ListUsers(uc tsm.UsersClient) {
	ul, err := uc.ListUsers()
	if err != nil {
		Lerror(err)
		return
	}
	users := make([]userdisp, len(ul))
	for i, u := range ul {
		//fmt.Printf("%v.\t%20s %20s %20s %20s\n", i+1, u.UserID, u.Description, u.DisplayName, u.AuthenticationType)
		users[i] = userdisp{Name: u.UserID, Role: u.Role, Dispname: u.DisplayName, AuthType: u.AuthenticationType}
	}
	sel := promptui.Select{Label: "Existing users"}
	sel.Items = users
	templates := &promptui.SelectTemplates{
		Label:    "{{ . }}?",
		Active:   " {{.Name | cyan}} ",
		Inactive: "  {{.Name}} ",
		Selected: " {{.Name}}",
		Details: `
--------- User {{.Name}} ----------
{{ "D.Name:" | faint }} {{ .Dispname }}
{{ "Role:" | faint }} {{ .Role }}
{{ "Authentication:" | faint }}	{{.AuthType }}`,
	}
	sel.Templates = templates
	sel.Run()
}
