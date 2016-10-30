package bperm

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bperm/backend"
)

var userstate, _ = NewUserStateSimple()

func TestNewUserStateDatabase(t *testing.T) {
	_ = userstate.Database()
}

func TestAddUser(t *testing.T) {
	u := &backend.User{
		Name:             "carlo",
		Email:            "carlo@mail.com",
		Username:         "hunter1",
		Admin:            false,
		Confirmed:        false,
		ConfirmationCode: "1345",
		Password:         "4321",
	}
	err := userstate.AddUser(u)
	if err == nil {
		t.Fatal(err)
	}
	u = &backend.User{
		Name:             "carlo",
		Email:            "carlo@mail.com",
		Username:         "hunter1",
		Admin:            false,
		Confirmed:        false,
		ConfirmationCode: "1345",
		Password:         "4321Asfdg@",
	}
	err = userstate.AddUser(u)
	if err != nil {
		t.Fatal(err)
	}
	u = &backend.User{
		Name:             "carlo",
		Username:         "hunter1",
		Admin:            false,
		Confirmed:        false,
		ConfirmationCode: "1345",
		Password:         "4321Asfdg@",
	}
	err = userstate.AddUser(u)
	if err == nil {
		t.Fatal(err)
	}
	u = &backend.User{
		Name:             "carlo",
		Email:            "carlo@mail.com",
		Username:         "hunter1",
		Admin:            false,
		Confirmed:        false,
		ConfirmationCode: "1345",
	}
	err = userstate.AddUser(u)
	if err == nil {
		t.Fatal(err)
	}
	u = &backend.User{
		Name:             "carlo",
		Email:            "carlo@mail.com",
		Admin:            false,
		Confirmed:        false,
		ConfirmationCode: "1345",
		Password:         "4321Asfdg@",
	}
	err = userstate.AddUser(u)
	if err == nil {
		t.Fatal(err)
	}

}

func TestSetUserStatus(t *testing.T) {
	err := userstate.SetUserStatus("hunter1", Confirmed, true)
	if err != nil {
		t.Fatal(err)
	}

	err = userstate.SetUserStatus("hunter1", Password, "4321Asdg@")
	if err != nil {
		t.Fatal(err)
	}

	err = userstate.SetUserStatus("hunter1", Active, true)
	if err != nil {
		t.Fatal(err)
	}

	err = userstate.SetUserStatus("hunter1", Admin, true)
	if err != nil {
		t.Fatal(err)
	}

	err = userstate.SetUserStatus("hunter1", Loggedin, true)
	if err != nil {
		t.Fatal(err)
	}

	u, err := userstate.GetUser("hunter1")
	if err != nil {
		t.Fatal(err)
	}

	if u.Admin != true || u.Confirmed != true || u.Active != true {
		t.Fatal("User not updated\n")
	}
}

func TestGetUserStatus(t *testing.T) {
	boolprops := []UserProperty{
		Admin,
		Confirmed,
		Loggedin,
	}

	for _, val := range boolprops {
		res, err := userstate.GetUserStatus("hunter1", val)
		if err != nil {
			t.Fatal(err)
		}
		admin := res.(bool)
		if admin != true {
			t.Fatal("Should be true")
		}
	}

	res, err := userstate.GetUserStatus("hunter1", Email)
	if err != nil {
		t.Fatal(err)
	}
	email := res.(string)
	if email != "bob@zombo.com" {
		t.Fatal("Should be true")
	}

}

func TestGetHasUser(t *testing.T) {
	has := userstate.HasUser("bob")
	if !has {
		t.Fatal("should have user\n")
	}

	_, err := userstate.GetUser("bob")
	if err != nil {
		t.Fatal(err)
	}

}

// shitting with identity type error
func TestGetAll(t *testing.T) {
	usernames, err := userstate.GetAll("Username")
	if err != nil {
		t.Fatal(err)
	}

	if len(usernames) == 0 {
		t.Fatal("Ops something went wrong, got 0 usernames.")
	}
}

func TestGetAllFiltered(t *testing.T) {
	confirmed, err := userstate.GetAllFiltered("Name", "Confirmed =", "true")
	if err != nil {
		t.Fatal(err)
	}

	if len(confirmed) != 1 {
		t.Fatal("Should have got 1 confirmed user.")
	}
}

func TestCheckUserPassword(t *testing.T) {
	ok := userstate.CheckUserPassword("carlo@mail.com", "14321Asfdg@")
	if !ok {
		t.Fatal("User password should match")
	}
}

func TestIsPasswordAllowed(t *testing.T) {
	err := IsPasswordAllowed("hunter1", "hunter1")
	if err == nil {
		t.Fatal("Should have returned an error")
	}

	err = IsPasswordAllowed("hunter1", "hunter1carlo")
	if err == nil {
		t.Fatal("Should have returned an error")
	}

	err = IsPasswordAllowed("hunter1", "1234")
	if err == nil {
		t.Fatal("Should have returned an error")
	}

	err = IsPasswordAllowed("hunter1", "12344567890")
	if err == nil {
		t.Fatal("Should have returned an error")
	}

	err = IsPasswordAllowed("hunter1", "12344567890adlj")
	if err == nil {
		t.Fatal("Should have returned an error")
	}

	err = IsPasswordAllowed("hunter1", "QWETT4567890adlj")
	if err == nil {
		t.Fatal("Should have returned an error")
	}

	err = IsPasswordAllowed("hunter1", "QWETT456#7890adlj")
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetUserByCode(t *testing.T) {
	_, err := userstate.GetUserByConfirmationCode("1345")
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetCurrentUserNicknameFail(t *testing.T) {
	req := &http.Request{}
	_, err := userstate.GetCurrentUserNickname(req)
	if err == nil {
		t.Fatal(err)
	}
}

func TestIsCurrentUserAdminFail(t *testing.T) {
	req := &http.Request{}
	_, err := userstate.IsCurrentUserAdmin(req)
	if err == nil {
		t.Fatal(err)
	}
}

func TestLoginFail(t *testing.T) {
	w := httptest.NewRecorder()
	err := userstate.Login(w, "hunter1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestLogoutFail(t *testing.T) {
	err := userstate.Logout("hunter1")
	if err != nil {
		t.Fatal(err)
	}

}

func TestClose(t *testing.T) {
	userstate.Close()
}
