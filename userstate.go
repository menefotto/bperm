package bperm

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	// Database interfaces
	"github.com/bperm/backend"
	"github.com/bperm/bcookie"
	"github.com/bperm/randomstring"
)

const (
	defaultFilename           = "waterandboards-auth"
	minConfirmationCodeLength = 32 // minimum length of the confirmation code
)

// The UserState struct holds the pointer to the underlying database and a few other settings
type UserState struct {
	users             backend.Db // A db or users with different fields ("loggedin", "confirmed") etc
	secureCookie      bcookie.SecureType
	cookieSecret      string // Secret for storing secure cookies
	cookieTime        int64  // How long a cookie should last, in seconds
	passwordAlgorithm string //default to bcrupt+
}

// NewUserStateSimple creates a new UserState struct that can be used for managing users.
// The random number generator will be seeded after generating the cookie secret.
func NewUserStateSimple() (*UserState, error) {
	// connection string | initialize random generator after generating the cookie secret
	return NewUserState(defaultFilename, true)
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
	secret := randomstring.GenReadable(30)
	if randomseed {
		rand.Seed(time.Now().UnixNano())
	}

	// Cookies lasts for 24 hours by default. Specified in seconds.
	// Default password hashing algorithm is "bcrypt+", which is the same as
	// "bcrypt", but with backwards compatibility for checking sha256 hashes.
	// "bcrypt+", "bcrypt" or "sha256"
	return &UserState{&db, bcookie.New(), secret, 3600 * 24, "bcrypt+"}, nil
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
	username, err := state.secureCookie.Get(req, "user", state.cookieSecret)
	if err != nil {
		return "", err
	}

	if username == "" {
		return "", errors.New("Could not get username is empty :(")
	}

	return "", errors.New("Could not retrieve the username from browser cookie")
}

// SetUsernameCookie stores the given username in a cookie in the browser, if possible.
// Will return an error if the username is empty or the user does not exist.
func (state *UserState) SetUsernameIntoCookie(w http.ResponseWriter, username string) error {
	if username == "" {
		return errors.New("Can't set cookie for empty username")
	}
	if !state.HasUser(username) {
		return errors.New("Can't store cookie for non-existsing user")
	}
	// Create a cookie that lasts for a while ("timeout" seconds),
	// this is the equivalent of a session for a given username.
	err := state.secureCookie.SetPath(w, "user", username, state.cookieTime, "/", state.cookieSecret)
	if err != nil {
		return err
	}

	return nil
}

// CookieTimeout returns the current login cookie timeout, in seconds.
func (state *UserState) GetCookieTimeout(username string) int64 {
	return state.cookieTime
}

// SetCookieTimeout sets how long a login cookie should last, in seconds.
func (state *UserState) SetCookieTimeout(cookieTime int64) {
	state.cookieTime = cookieTime
}

// CookieSecret returns the current cookie secret
func (state *UserState) GetCookieSecret() string {
	return state.cookieSecret
}

// SetCookieSecret sets the current cookie secret
func (state *UserState) SetCookieSecret(cookieSecret string) {
	state.cookieSecret = cookieSecret
}

// ClearCookie tries to clear the user cookie by setting it to be expired.
// Some browsers *may* be configured to keep cookies even after this.
func (state *UserState) ClearCookie(w http.ResponseWriter) {
	state.secureCookie.Del(w, "user", "/")
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
	case prop == Email:
		result, err = user.Email, nil
	case prop == Username:
		result, err = user.Username, nil
	default:
		result, err = false, fmt.Errorf("Property is not gettable or defined\n")
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
		user.Password, err = state.HashPassword(username, val.(string))
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
	err := state.users.Put(user.Email, user)
	if err != nil {
		return err
	}

	return nil
}

// CurrentUserAdmin checks if the current user is logged in and has administrator rights.
func (state *UserState) IsCurrentUserAdmin(req *http.Request) bool {
	username, err := state.GetUsernameFromCookie(req)
	if err != nil {
		return false
	}

	login, _ := state.GetUserStatus(username, Loggedin)
	admin, _ := state.GetUserStatus(username, Admin)

	return login.(bool) && admin.(bool)
}

// Username is a convenience function for returning the current username
// (from the browser cookie), or an empty string.
func (state *UserState) GetCurrentUserUsername(req *http.Request) string {
	username, err := state.GetUsernameFromCookie(req)
	if err != nil {
		return ""
	}
	return username
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
func (state *UserState) Logout(username string) {
	_ = state.SetUserStatus(username, Loggedin, false)
}

// AlreadyHasConfirmationCode goes through all the confirmationCodes of all
// the unconfirmed users and checks if this confirmationCode already is in use.
func (state *UserState) AlreadyHasConfirmationCode(confirmationCode string) bool {
	unconfirmedUsernames, err := state.GetAllFiltered("Users", "Confirmed =", "false")
	if err != nil {
		return false
	}
	for _, aUsername := range unconfirmedUsernames {
		aConfirmationCode, err := state.GetUserStatus(aUsername, ConfirmationCode)
		if err != nil {
			// If the confirmation code can not be found, that's okay too
			return false
		}
		if confirmationCode == aConfirmationCode.(string) {
			// Found it
			return true
		}
	}
	return false
}

// FindUserByConfirmationCode tries to find the corresponding username,
// given a unique confirmation code.
func (state *UserState) FindUserByConfirmationCode(confirmationcode string) (string, error) {
	unconfirmedUsernames, err := state.GetAllFiltered("Username", "Confirmed = ", "false")
	if err != nil {
		return "", errors.New("All existing users are already confirmed.")
	}

	// Find the username by looking up the confirmationcode on unconfirmed users
	username := ""
	for _, aUsername := range unconfirmedUsernames {
		aConfirmationCode, err := state.GetUserStatus(aUsername, ConfirmationCode)
		if err != nil {
			// If the confirmation code can not be found, just skip this one
			continue
		}
		if confirmationcode == aConfirmationCode.(string) {
			// Found the right user
			username = aUsername
			break
		}
	}

	// Check that the user is there
	if username == "" {
		return username, errors.New("The confirmation code is no longer valid.")
	}
	hasUser := state.HasUser(username)
	if !hasUser {
		return username, errors.New("The user that is to be confirmed no longer exists.")
	}

	return username, nil
}

// GenerateUniqueConfirmationCode generates a unique confirmation code that
// can be used for confirming users.
func (state *UserState) GenerateUniqueConfirmationCode() (string, error) {
	const maxConfirmationCodeLength = 100 // when are the generated confirmation codes unreasonably long
	length := minConfirmationCodeLength
	confirmationCode := randomstring.GenReadable(length)
	for state.AlreadyHasConfirmationCode(confirmationCode) {
		// Increase the length of the confirmationCode random string every time there is a collision
		length++
		confirmationCode = randomstring.GenReadable(length)
		if length > maxConfirmationCodeLength {
			// This should never happen
			return confirmationCode, errors.New("Too many generated confirmation codes are not unique!")
		}
	}
	return confirmationCode, nil
}

// PasswordHash returns the password hash for the given username.
func (state *UserState) GetPasswordHash(username string) (string, error) {
	user, err := state.users.Get(username)
	if err != nil {
		return "", err
	}

	return user.Password, nil
}

// HashPassword takes a password and creates a password hash.
// It also takes a username, since some algorithms may use it for salt.
func (state *UserState) HashPassword(username, password string) (string, error) {
	var (
		err  error
		hash string
	)

	hash, err = hashBcrypt(password)
	if err != nil {
		return "", err
	}

	return hash, nil
}

// IsUserPassword checks if a password is correct. "username" is needed because
// it may be part of the hash for some password hashing algorithms.
func (state *UserState) IsUserPassword(username, password string) bool {

	if !state.HasUser(username) {
		return false
	}

	// Retrieve the stored password hash
	hash, err := state.GetPasswordHash(username)
	if err != nil {
		return false
	}
	if len(hash) == 0 {
		return false
	}

	// Check the password with the right password algorithm
	switch state.passwordAlgorithm {
	case "bcrypt", "bcrypt+":
		return correctBcrypt(hash, password)
	}
	return false
}

// IsPasswordAllowed only checks if the given username and password are
// different and if they only contain letters, numbers and/or underscore.
// For checking if a given password is correct, use the `CorrectPassword`
// function instead.
func IsPasswordAllowed(username, password string) error {
	const (
		equal    = "Username and password can't be equal!\n"
		distance = "Username and password can't contain same words!\n"
		alnum    = "Password does not have numbers and letters.\n"
		special  = "Password does not have one of the following:!@#$%^+&*~-_\n"
		short    = "Password does not have 9 characters\n"
	)
	usern := strings.ToLower(username)
	passw := strings.ToLower(password)
	if usern == passw {
		return fmt.Errorf(equal)
	}

	editd := randomstring.LevenshteinDistance(usern, passw)
	if editd < len(password)-len(password)/4 {
		return fmt.Errorf(distance)
	}

	if len(password) < 9 {
		return fmt.Errorf(short)
	}

	rex := regexp.MustCompile(`[[:alnum:]]+`)
	if !rex.Match([]byte(password)) {
		return fmt.Errorf(alnum)
	}

	var (
		ok         = false
		characters = []string{"!#$%&*+-?@^_~"}
	)

	for i := 0; i < len(characters); i++ {
		ok = strings.ContainsAny(password, characters[i])
		if !ok && i == len(characters)-1 {
			return fmt.Errorf(special)
		}
	}

	return nil
}
