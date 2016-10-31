package bperm

import (
	"context"
	"errors"

	"cloud.google.com/go/datastore"

	"github.com/bperm/randomstring"
	"github.com/bperm/userstore"
)

type UserManager struct {
	users           userstore.Db // A db or users with states
	passwordChecker PasswordValidator
}

func NewUserManager(projectId string) (*UserManager, error) {
	var db userstore.Datastore

	err := db.Open(projectId, "Users")
	if err != nil {
		return nil, err
	}

	return &UserManager{db, DefaultPasswordValidator}
}

// AddUser creates a user and hashes the password, does not check for rights.
// The given data must be valid.
func (mng *UserManager) AddUser(user *userstore.User) error {

	switch {
	case user.Email == "":
		return errors.New("Email field is required\n")
	case user.Username == "":
		return errors.New("Username field is required\n")
	case user.Password == "":
		return errors.New("Password field is required\n")
	}

	if err := mng.passwordChecker(user.Username, user.Password); err != nil {
		return err
	}

	hashed, err := HashBcrypt(user.Password)
	if err != nil {
		return err
	}

	user.Password = hashed
	user.ConfirmationCode = randomstring.GenReadable(32)
	err = state.users.Put(user.Email, user)
	if err != nil {
		return err
	}

	return nil
}

// HasUser checks if the given username exists.
func (mng *UserManager) HasUser(username string) bool {
	_, err := mng.users.Get(username)
	if err != nil {
		return false
	}
	return true
}

func (state *UserManager) GetUser(username string) (*userstore.User, error) {
	user, err := mng.users.Get(username)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// UserProperty identifies what filed we want to change from the User
type UserProperty int

const (
	Admin UserProperty = iota
	Confirmed
	ConfirmationCode
	Loggedin
	Password
	Active
	Email
	Username
)

// GetAll returns a list of all "what" selector/ usernames, email etc./ only string fields
func (mng *UserManager) GetAll(what string) ([]string, error) {
	//return state.usernames.GetAll()
	usernames := []string{}

	ctx := context.Background()
	store := mng.users.(*userstore.Datastore)
	client := store.Backend()

	_, err := client.GetAll(ctx, datastore.NewQuery("Users").Project(what), usernames)
	if err != nil {
		return nil, err
	}

	return usernames, nil
}

// GetAllFiltered returns a list from all the registered users with the selector
// what, and the Filters them by filter
// For examplte if you would love to get all users name of non confirmed users
// you would call GetAllFiltered("Username",Confirmed =", "false")
func (mng *UserManager) GetAllFiltered(what, filter, filterVal string) ([]string, error) {
	usernames := []string{}

	ctx := context.Background()
	store := state.users.(*userstore.Datastore)
	client := store.Backend()

	_, err := client.GetAll(ctx, datastore.NewQuery("Users").
		Filter(filter, filterVal).
		Project(what), usernames)

	if err != nil {
		return nil, err
	}

	return usernames, nil
}

func (mng *UserManager) GetUserStatus(id string, prop UserProperty) (result interface{}, err error) {
	user := &userstore.User{}
	user, err = mng.users.Get(id)
	if err != nil {
		return false, err
	}

	switch {
	case prop == Admin:
		result, err = user.Admin, nil
	case prop == Confirmed:
		result, err = user.Confirmed, nil
	case prop == ConfirmationCode:
		result, err = user.ConfirmationCode, nil
	case prop == Loggedin:
		result, err = user.Loggedin, nil
	case prop == Password:
		result, err = user.Password, nil
	case prop == Email:
		result, err = user.Email, nil
	case prop == Username:
		result, err = user.Username, nil
	default:
		result, err = false, errors.New("Property is not defined\n")
	}

	return
}

func (mng *UserManager) SetUserStatus(username string, prop UserProperty, val interface{}) error {
	user, err := mng.users.Get(username)
	if err != nil {
		return err
	}

	switch {
	case prop == Confirmed:
		user.Confirmed = val.(bool)
	case prop == Email:
		user.Email = val.(string)
	case prop == Password:
		if err = IsPasswordAllowed(username, val.(string)); err != nil {
			return err
		}
		user.Password, err = HashBcrypt(val.(string))
		if err != nil {
			return err
		}
	case prop == Active:
		user.Active = val.(bool)
		if val.(bool) == true {
			user.Loggedin = false
		}
	case prop == Admin:
		user.Admin = val.(bool)
	case prop == Loggedin:
		user.Loggedin = val.(bool)
	}

	err = mng.users.Put(username, user)
	if err != nil {
		return err
	}

	return nil
}

// CheckPasswordMatch checks if a password is correct. "username" is needed because
// it may be part of the hash for some password hashing algorithms.
func (mng *UserSession) CheckPasswordMatch(username, password string) bool {

	if !mng.HasUser(username) {
		return false
	}

	// Retrieve the stored password hash
	user, err := mng.GetUser(username)
	if err != nil {
		return false
	}

	if len(user.Password) == 0 {
		return false
	}

	// Check the password with the right password algorithm
	switch state.passwordAlgorithm {
	case "bcrypt", "bcrypt+":
		return correctBcrypt(user.Password, password)
	}

	return false
}

// Database retrieves the underlying database
func (mng *UserManager) Backend() userstore.Db {
	return mng.users
}

// Close the connection to the database host
func (mng *UserManager) Close() {
	mng.users.Close()
}
