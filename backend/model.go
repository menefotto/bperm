package backend

type User struct {
	Email            string
	Username         string
	Name             string
	LastName         string
	Password         string
	PhotoUrl         string
	Confirmed        bool
	ConfirmationCode string
	Admin            bool
	Loggedin         bool
	Active           bool
}
