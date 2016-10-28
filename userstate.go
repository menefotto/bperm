package bperm

import (
	"context"
	"errors"
	"fmt"
	"log"
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
	defaultFilename = "waterandboards-auth"
)

var (
	minConfirmationCodeLength = 20 // minimum length of the confirmation code
)

// The UserState struct holds the pointer to the underlying database and a few other settings
type UserState struct {
	users             backend.Db // A db or users with different fields ("loggedin", "confirmed") etc
	cookieSecret      string     // Secret for storing secure cookies
	cookieTime        int64      // How long a cookie should last, in seconds
	passwordAlgorithm string     // The hashing algo to utilize default: "bcrypt+" allowed: ("sha256", "bcrypt", "bcrypt+")
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

	log.Println("before opening db")
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
	return &UserState{&db, secret, 3600 * 24, "bcrypt+"}, nil
}

// Database retrieves the underlying database
func (state *UserState) Database() backend.Db {
	return state.users
}

// Close the connection to the database host
func (state *UserState) Close() {
	state.users.Close()
}

// UserRights checks if the current user is logged in and has user rights.
func (state *UserState) UserRights(req *http.Request) bool {
	username, err := state.UsernameCookie(req)
	if err != nil {
		return false
	}
	return state.IsLoggedIn(username)
}

// HasUser checks if the given username exists.
func (state *UserState) HasUser(username string) bool {
	_, err := state.users.Get(username)
	if err != nil {
		log.Println("user not found :", err)
		return false
	}
	return true
}

// IsConfirmed checks if a user is confirmed (can be used for "e-mail confirmation").
// TODO add error reporting
func (state *UserState) IsConfirmed(username string) bool {
	user, err := state.users.Get(username)
	if err != nil {
		return false
	}
	return user.Confirmed
}

// IsLoggedIn checks if a user is logged in.
func (state *UserState) IsLoggedIn(username string) bool {
	user, err := state.users.Get(username)
	if err != nil {
		// Returns "no" if the status can not be retrieved
		return false
	}
	return user.Loggedin
}

// AdminRights checks if the current user is logged in and has administrator rights.
func (state *UserState) AdminRights(req *http.Request) bool {
	username, err := state.UsernameCookie(req)
	if err != nil {
		return false
	}
	return state.IsLoggedIn(username) && state.IsAdmin(username)
}

// IsAdmin checks if a user is an administrator.
func (state *UserState) IsAdmin(username string) bool {
	user, err := state.users.Get(username)
	if err != nil {
		return false
	}
	return user.Admin
}

// UsernameCookie retrieves the username that is stored in a cookie in the browser, if available.
func (state *UserState) UsernameCookie(req *http.Request) (string, error) {
	username, ok := bcookie.Get(req, "user", state.cookieSecret)
	if ok && (username != "") {
		return username, nil
	}
	return "", errors.New("Could not retrieve the username from browser cookie")
}

// SetUsernameCookie stores the given username in a cookie in the browser, if possible.
// Will return an error if the username is empty or the user does not exist.
func (state *UserState) SetUsernameCookie(w http.ResponseWriter, username string) error {
	if username == "" {
		return errors.New("Can't set cookie for empty username")
	}
	if !state.HasUser(username) {
		return errors.New("Can't store cookie for non-existsing user")
	}
	// Create a cookie that lasts for a while ("timeout" seconds),
	// this is the equivivalent of a session for a given username.
	err := bcookie.SetPath(w, "user", username, state.cookieTime, "/", state.cookieSecret)
	if err != nil {
		return err
	}

	return nil
}

// AllUsernames returns a list of all usernames.
func (state *UserState) AllUsernames() ([]string, error) {
	//return state.usernames.GetAll()
	usernames := []string{}

	ctx := context.Background()
	store := state.users.(*backend.Datastore)
	client := store.Backend()

	_, err := client.GetAll(ctx, datastore.NewQuery("Users").Project("Username"), usernames)
	if err != nil {
		return nil, err
	}

	return usernames, nil
}

// Email returns the email address for the given username.
func (state *UserState) Email(username string) (string, error) {
	user, err := state.users.Get(username)
	if err != nil {
		return "", err
	}

	return user.Email, nil
}

// PasswordHash returns the password hash for the given username.
func (state *UserState) PasswordHash(username string) (string, error) {
	user, err := state.users.Get(username)
	if err != nil {
		return "", err
	}

	return user.Password, nil
}

// AllUnconfirmedUsernames returns a list of all registered users that are not yet confirmed.
//TODO expose query filter in the interface query filter
func (state *UserState) AllUnconfirmedUsernames() ([]string, error) {
	usernames := []string{}

	ctx := context.Background()
	store := state.users.(*backend.Datastore)
	client := store.Backend()

	_, err := client.GetAll(ctx, datastore.NewQuery("Users").Filter("Confirmed =", "false").Project("Username"), usernames)
	if err != nil {
		return nil, err
	}

	return usernames, nil
}

// ConfirmationCode returns the stored confirmation code for a specific user.
func (state *UserState) ConfirmationCode(username string) (string, error) {
	user, err := state.users.Get(username)
	if err != nil {
		return "", err
	}

	return user.ConfirmationCode, nil
}

// AddUnconfirmed adds a user to a list of users that are registered, but not confirmed.
func (state *UserState) AddUnconfirmed(username, confirmationCode string) error {
	user, err := state.users.Get(username)
	if err != nil {
		return err
	}

	user.ConfirmationCode = confirmationCode
	err = state.users.Put(username, user)
	if err != nil {
		return err
	}

	return nil
}

// RemoveUnconfirmed removes a user from a list of users that are registered, but not confirmed.
func (state *UserState) RemoveUnconfirmed(username string) {
	//has become a nops since there not the data structure any longer
	return
}

// MarkConfirmed marks a user as being confirmed.
func (state *UserState) MarkConfirmed(username string) error {
	user, err := state.users.Get(username)
	if err != nil {
		return err
	}

	user.Confirmed = true
	err = state.users.Put(username, user)
	if err != nil {
		return err
	}

	return nil
}

// RemoveUser removes a user and the login status for this user.
func (state *UserState) RemoveUser(username string) error {
	// Remove additional data as well
	//state.users.DelKey(username, "loggedin")
	err := state.users.Del(username)
	if err != nil {
		return fmt.Errorf("Failed to logout user %s\n", username)
	}

	return nil
}

// SetAdminStatus marks a user as an administrator.
func (state *UserState) SetAdminStatus(username string) error {
	user, err := state.users.Get(username)
	if err != nil {
		return err
	}

	user.Admin = true
	err = state.users.Put(username, user)
	if err != nil {
		return err
	}

	return nil
}

// RemoveAdminStatus removes the administrator status from a user.
func (state *UserState) RemoveAdminStatus(username string) error {
	user, err := state.users.Get(username)
	if err != nil {
		return err
	}

	user.Admin = false
	err = state.users.Put(username, user)
	if err != nil {
		return err
	}

	return nil
}

// addUserUnchecked creates a user from the username and password hash, does not check for rights.
func (state *UserState) addUserUnchecked(username, passwdHash, email string) error {
	// Add the user
	user := &backend.User{}
	// Add password and email
	user.Username = username
	user.Password = passwdHash
	user.Email = email
	user.Loggedin = false
	user.Confirmed = false
	user.Admin = false
	// Addditional fields
	if err := state.users.Put(email, user); err != nil {
		return err
	}

	return nil
}

// AddUser creates a user and hashes the password, does not check for rights.
// The given data must be valid.
func (state *UserState) AddUser(username, password, email string) error {
	user := &backend.User{}
	// Add password and email
	user.Username = username
	user.Password, _ = state.HashPassword(username, password)
	user.Email = email
	user.Loggedin = false
	user.Confirmed = false
	user.Admin = false
	// Addditional fields

	err := state.users.Put(username, user)
	if err != nil {
		log.Println("Err: while adding user: ", err)
		return err
	}

	return nil
}

// SetLoggedIn marks a user as logged in.
// Use the Login function instead, unless cookies are not involved.
func (state *UserState) SetLoggedIn(username string) error {
	user, err := state.users.Get(username)
	if err != nil {
		return err
	}

	user.Loggedin = true
	err = state.users.Put(username, user)
	if err != nil {
		return err
	}

	return nil
}

// SetLoggedOut marks a user as logged out.
func (state *UserState) SetLoggedOut(username string) error {
	user, err := state.users.Get(username)
	if err != nil {
		return err
	}

	user.Loggedin = false
	err = state.users.Put(username, user)
	if err != nil {
		return err
	}

	return nil
}

// Login is a convenience function for logging a user in and storing the
// username in a cookie, returns an error if the cookie could not be set.
func (state *UserState) Login(w http.ResponseWriter, username string) error {
	_ = state.SetLoggedIn(username)
	return state.SetUsernameCookie(w, username)
}

// ClearCookie tries to clear the user cookie by setting it to be expired.
// Some browsers *may* be configured to keep cookies even after this.
func (state *UserState) ClearCookie(w http.ResponseWriter) {
	bcookie.Del(w, "user", "/")
}

// Logout is a convenience function for logging out a user.
func (state *UserState) Logout(username string) {
	_ = state.SetLoggedOut(username)
}

// Username is a convenience function for returning the current username
// (from the browser cookie), or an empty string.
func (state *UserState) Username(req *http.Request) string {
	username, err := state.UsernameCookie(req)
	if err != nil {
		return ""
	}
	return username
}

// CookieTimeout returns the current login cookie timeout, in seconds.
func (state *UserState) CookieTimeout(username string) int64 {
	return state.cookieTime
}

// SetCookieTimeout sets how long a login cookie should last, in seconds.
func (state *UserState) SetCookieTimeout(cookieTime int64) {
	state.cookieTime = cookieTime
}

// CookieSecret returns the current cookie secret
func (state *UserState) CookieSecret() string {
	return state.cookieSecret
}

// SetCookieSecret sets the current cookie secret
func (state *UserState) SetCookieSecret(cookieSecret string) {
	state.cookieSecret = cookieSecret
}

// PasswordAlgo returns the current password hashing algorithm.
func (state *UserState) PasswordAlgo() string {
	return state.passwordAlgorithm
}

/*SetPasswordAlgo determines which password hashing algorithm should be used.
 *
 * The default value is "bcrypt+".
 *
 * Possible values are:
 *    bcrypt  -> Store and check passwords with the bcrypt hash.
 *    sha256  -> Store and check passwords with the sha256 hash.
 *    bcrypt+ -> Store passwords with bcrypt, but check with both
 *               bcrypt and sha256, for backwards compatibility
 *               with old passwords that has been stored as sha256.
 */
func (state *UserState) SetPasswordAlgo(algorithm string) error {
	switch algorithm {
	case "sha256", "bcrypt", "bcrypt+":
		state.passwordAlgorithm = algorithm
	default:
		return errors.New("Permissions: " + algorithm + " is an unsupported encryption algorithm")
	}
	return nil
}

// HashPassword takes a password and creates a password hash.
// It also takes a username, since some algorithms may use it for salt.
func (state *UserState) HashPassword(username, password string) (string, error) {
	var (
		err  error
		hash string
	)

	switch state.passwordAlgorithm {
	case "sha256":
		hash, err = hashSha256(state.cookieSecret, username, password)
	case "bcrypt", "bcrypt+":
		hash, err = hashBcrypt(password)
	}
	// Only valid password algorithms should be allowed to set
	if err != nil {
		return "", err
	}

	return hash, nil
}

// SetPassword sets/changes the password for a user.
// Does not take a password hash, will hash the password string.
func (state *UserState) SetPassword(username, password string) error {
	user, err := state.users.Get(username)
	if err != nil {
		return err
	}

	user.Password, _ = state.HashPassword(username, password)
	err = state.users.Put(username, user)
	if err != nil {
		return err
	}

	return nil
}

// Return the stored hash, or an empty byte slice.
func (state *UserState) storedHash(username string) []byte {
	hashString, err := state.PasswordHash(username)
	if err != nil {
		return []byte{}
	}
	return []byte(hashString)
}

// CorrectPassword checks if a password is correct. "username" is needed because
// it may be part of the hash for some password hashing algorithms.
func (state *UserState) CorrectPassword(username, password string) bool {

	if !state.HasUser(username) {
		return false
	}

	// Retrieve the stored password hash
	hash := state.storedHash(username)
	if len(hash) == 0 {
		return false
	}

	// Check the password with the right password algorithm
	switch state.passwordAlgorithm {
	case "sha256":
		return correctSha256(hash, state.cookieSecret, username, password)
	case "bcrypt":
		return correctBcrypt(hash, password)
	case "bcrypt+": // for backwards compatibility with sha256
		if isSha256(hash) && correctSha256(hash, state.cookieSecret, username, password) {
			return true
		}
		return correctBcrypt(hash, password)
	}
	return false
}

// AlreadyHasConfirmationCode goes through all the confirmationCodes of all
// the unconfirmed users and checks if this confirmationCode already is in use.
func (state *UserState) AlreadyHasConfirmationCode(confirmationCode string) bool {
	unconfirmedUsernames, err := state.AllUnconfirmedUsernames()
	if err != nil {
		return false
	}
	for _, aUsername := range unconfirmedUsernames {
		aConfirmationCode, err := state.ConfirmationCode(aUsername)
		if err != nil {
			// If the confirmation code can not be found, that's okay too
			return false
		}
		if confirmationCode == aConfirmationCode {
			// Found it
			return true
		}
	}
	return false
}

// FindUserByConfirmationCode tries to find the corresponding username,
// given a unique confirmation code.
func (state *UserState) FindUserByConfirmationCode(confirmationcode string) (string, error) {
	unconfirmedUsernames, err := state.AllUnconfirmedUsernames()
	if err != nil {
		return "", errors.New("All existing users are already confirmed.")
	}

	// Find the username by looking up the confirmationcode on unconfirmed users
	username := ""
	for _, aUsername := range unconfirmedUsernames {
		aConfirmationCode, err := state.ConfirmationCode(aUsername)
		if err != nil {
			// If the confirmation code can not be found, just skip this one
			continue
		}
		if confirmationcode == aConfirmationCode {
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

// Confirm marks a user as confirmed, and removes the username from the list
// of unconfirmed users.
func (state *UserState) Confirm(username string) {
	// Remove from the list of unconfirmed usernames
	state.RemoveUnconfirmed(username)

	// Mark user as confirmed
	_ = state.MarkConfirmed(username)
}

// ConfirmUserByConfirmationCode takes a unique confirmation code and marks
// the corresponding unconfirmed user as confirmed.
func (state *UserState) ConfirmUserByConfirmationCode(confirmationcode string) error {
	/*username, err := state.FindUserByConfirmationCode(confirmationcode)
	if err != nil {
		return err
	}
	state.Confirm(username)*/
	return nil
}

// SetMinimumConfirmationCodeLength sets the minimum length of the user
// confirmation code. The default is 20.
func (state *UserState) SetMinimumConfirmationCodeLength(length int) {
	minConfirmationCodeLength = length
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

// ValidUsernamePassword only checks if the given username and password are
// different and if they only contain letters, numbers and/or underscore.
// For checking if a given password is correct, use the `CorrectPassword`
// function instead.
func ValidUsernamePassword(username, password string) error {
	const allowedLetters = "abcdefghijklmnopqrstuvwxyzæøåABCDEFGHIJKLMNOPQRSTUVWXYZÆØÅ_0123456789"
NEXT:
	for _, letter := range username {
		for _, allowedLetter := range allowedLetters {
			if letter == allowedLetter {
				continue NEXT // check the next letter in the username
			}
		}
		return errors.New("Only letters, numbers and underscore are allowed in usernames.")
	}
	if username == password {
		return errors.New("Username and password must be different, try another password.")
	}
	return nil
}
