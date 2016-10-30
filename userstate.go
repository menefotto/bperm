package bperm

import (
	"context"
	"errors"
	"math/rand"
	"net/http"
	"time"

	"cloud.google.com/go/datastore"
	// Database interfaces
	"github.com/bperm/backend"
	"github.com/bperm/bcookie"
	"github.com/bperm/randomstring"
)

const (
	DefaultProjectId = "waterandboards-auth"
)

// The UserState struct holds the pointer to the underlying database and a few other settings
type UserState struct {
	bcookie.SecureType
	users             backend.Db // A db or users with different fields ("loggedin", "confirmed") etc
	passwordAlgorithm string     //default to bcrupt+
}

// NewUserStateSimple creates a new UserState struct that can be used for managing users.
// The random number generator will be seeded after generating the cookie secret.
func NewUserStateSimple() (*UserState, error) {
	// connection string | initialize random generator after generating the cookie secret
	return NewUserState(DefaultProjectId, true)
}

// NewUserState creates a new UserState struct that can be used for managing users.
// connectionString may be on the form "username:password@host:port/database".
// If randomseed is true, the random number generator will be seeded after generating the cookie secret
// (true is a good default value).
func NewUserState(filename string, randomseed bool) (*UserState, error) {
	var db backend.Datastore

	err := db.Open(filename, "Users")
	if err != nil {
		return nil, err
	}

	// For the secure cookies
	// This must happen before the random seeding, or
	// else people will have to log in again after every server restart
	// Seed the random number generator
	if randomseed {
		rand.Seed(time.Now().UnixNano())
	}

	// Cookies lasts for 24 hours by default. Specified in seconds.
	// Default password hashing algorithm is "bcrypt+", which is the same as
	// "bcrypt", but with backwards compatibility for checking sha256 hashes.
	// "bcrypt+", "bcrypt" or "sha256"
	return &UserState{bcookie.New(), &db, "bcrypt+"}, nil
}

// Database retrieves the underlying database
func (state *UserState) Database() backend.Db {
	return state.users
}

// Close the connection to the database host
func (state *UserState) Close() {
	state.users.Close()
}

// HasUser checks if the given username exists.
func (state *UserState) HasUser(username string) bool {
	_, err := state.users.Get(username)
	if err != nil {
		return false
	}
	return true
}

func (state *UserState) GetUser(username string) (*backend.User, error) {
	user, err := state.users.Get(username)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// UsernameCookie retrieves the username that is stored in a cookie in the browser, if available.
// TODO make them part of the bcookie package
func (state *UserState) GetUsernameFromCookie(req *http.Request) (string, error) {
	username, err := state.Get(req, "user")
	if err != nil {
		return "", err
	}

	if username == "" {
		return "", errors.New("Could not get username, is empty :(")
	}

	return username, nil
}

// SetUsernameCookie stores the given username in a cookie in the browser, if possible.
// Will return an error if the username is empty or the user does not exist.
func (state *UserState) SetUsernameIntoCookie(w http.ResponseWriter, username string) error {
	if username == "" {
		return errors.New("Can't set cookie for empty username")
	}

	if !state.HasUser(username) {
		return errors.New("Can't store cookie for non-existing user")
	}
	// Create a cookie that lasts for a while ("timeout" seconds),
	// this is the equivalent of a session for a given username.
	err := state.SetPath(w, "user", username, "/")
	if err != nil {
		return err
	}

	return nil
}

// ClearCookie tries to clear the user cookie by setting it to be expired.
// Some browsers *may* be configured to keep cookies even after this.
func (state *UserState) ClearCookie(w http.ResponseWriter) {
	state.Del(w, "user", "/")
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

func (state *UserState) GetUserStatus(id string, prop UserProperty) (result interface{}, err error) {
	user := &backend.User{}
	user, err = state.users.Get(id)
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

func (state *UserState) SetUserStatus(username string, prop UserProperty, val interface{}) error {
	user, err := state.users.Get(username)
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

	err = state.users.Put(username, user)
	if err != nil {
		return err
	}

	return nil
}

// GetAll returns a list of all "what" selector/ usernames, email etc./ only string fields
func (state *UserState) GetAll(what string) ([]string, error) {
	//return state.usernames.GetAll()
	usernames := []string{}

	ctx := context.Background()
	store := state.users.(*backend.Datastore)
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
func (state *UserState) GetAllFiltered(what, filter, filterVal string) ([]string, error) {
	usernames := []string{}

	ctx := context.Background()
	store := state.users.(*backend.Datastore)
	client := store.Backend()

	_, err := client.GetAll(ctx, datastore.NewQuery("Users").
		Filter(filter, filterVal).
		Project(what), usernames)

	if err != nil {
		return nil, err
	}

	return usernames, nil
}

// AddUser creates a user and hashes the password, does not check for rights.
// The given data must be valid.
func (state *UserState) AddUser(user *backend.User) error {
	switch {
	case user.Email == "":
		return errors.New("Email field is required\n")
	case user.Username == "":
		return errors.New("Username field is required\n")
	case user.Password == "":
		return errors.New("Password field is required\n")
	}

	if err := IsPasswordAllowed(user.Username, user.Password); err != nil {
		return err
	}

	hashed, err := HashBcrypt(user.Password)
	if err != nil {
		return err
	}

	user.Password = hashed
	err = state.users.Put(user.Email, user)
	if err != nil {
		return err
	}

	return nil
}

// CurrentUserAdmin checks if the current user is logged in and has administrator rights.
func (state *UserState) IsCurrentUserAdmin(req *http.Request) (bool, error) {
	username, err := state.GetUsernameFromCookie(req)
	if err != nil {
		return false, err
	}

	login, err := state.GetUserStatus(username, Loggedin)
	if err != nil {
		return false, err
	}

	admin, err := state.GetUserStatus(username, Admin)
	if err != nil {
		return false, err
	}

	return login.(bool) && admin.(bool), nil
}

// Username is a convenience function for returning the current username
// (from the browser cookie), or an empty string.
func (state *UserState) GetCurrentUserNickname(req *http.Request) (string, error) {
	username, err := state.GetUsernameFromCookie(req)
	if err != nil {
		return "", err
	}
	return username, nil
}

// Login is a convenience function for logging a user in and storing the
// username in a cookie, returns an error if the cookie could not be set.
func (state *UserState) Login(w http.ResponseWriter, username string) error {
	user, err := state.GetUser(username)
	if err != nil {
		return err
	}

	if !user.Active {
		return errors.New("Username is not registered")
	}

	if err = state.SetUserStatus(username, Loggedin, true); err != nil {
		return err
	}

	return state.SetUsernameIntoCookie(w, username)
}

// Logout is a convenience function for logging out a user.
func (state *UserState) Logout(username string) error {
	return state.SetUserStatus(username, Loggedin, false)
}

// GetUserByConfirmationCode tries to find the corresponding username,
// given a unique confirmation code.
func (state *UserState) GetUserByConfirmationCode(confirmationcode string) (string, error) {
	users, err := state.GetAllFiltered("Username", "Confirmed = ", "false")
	if err != nil {
		return "", errors.New("All existing users are already confirmed.")
	}

	// Find the username by looking up the confirmationcode on unconfirmed users
	var nickname = ""
	for _, username := range users {
		code, err := state.GetUserStatus(username, ConfirmationCode)
		if err != nil {
			// If the confirmation code can not be found, just skip this one
			continue
		}
		if confirmationcode == code.(string) {
			// Found the right user
			nickname = username
			break
		}
	}

	// Check that the user is there
	if nickname == "" {
		return nickname, errors.New("The confirmation code is not valid.")
	}

	if ok := state.HasUser(nickname); !ok {
		return nickname, errors.New("The user no longer exists.")
	}

	return nickname, nil
}

// GenConfirmationCode generates an almost unique confirmation code that
// can be used for confirming users.
func (state *UserState) GenConfirmationCode() string {
	return randomstring.GenReadable(64)
}

// CheckUserPassword checks if a password is correct. "username" is needed because
// it may be part of the hash for some password hashing algorithms.
func (state *UserState) CheckUserPassword(username, password string) bool {

	if !state.HasUser(username) {
		return false
	}

	// Retrieve the stored password hash
	user, err := state.GetUser(username)
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
