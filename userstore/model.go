package userstore

type User struct {
	Email            string
	Username         string
	Name             string
	MiddleName       string
	LastName         string
	Password         string
	PhotoUrl         string
	ConfirmationCode string
	Confirmed        bool
	Admin            bool
	Loggedin         bool
	Active           bool
}
