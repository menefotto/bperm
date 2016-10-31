package bperm

import "github.com/cookies"

const (
	DefaultProjectId = "waterandboards-auth" // currently set like this bacuse of I have to change the name in app engine
)

// The UserSession struct holds the pointer to the underlying database and a few other settings
type Session struct {
	cookies.CookieMng // abstract a cookie secure cookie manager
	mng               *UserManager
}

// NewUserSessionSimple creates a new UserSession struct that can be used for managing users.
// The random number generator will be seeded after generating the cookie secret.
func NewSimpleSession() (*Session, error) {
	// connection string | initialize random generator after generating the cookie secret
	return NewUserSession(DefaultProjectId, true)
}

// NewUserSession creates a new UserSession struct that can be used for managing users.
// connectionString may be on the form "username:password@host:port/database".
// If randomseed is true, the random number generator will be seeded after generating the cookie secret
// (true is a good default value).
func NewSession(projectId string) (*UserSession, error) {
	mng, err := NewUserManager(projectId)
	if err != nil {
		return nil, err
	}

	// Cookies lasts for 24 hours by default. Specified in seconds.
	// Default password hashing algorithm is "bcrypt+", which is the same as
	// "bcrypt", but with backwards compatibility for checking sha256 hashes.
	// "bcrypt+", "bcrypt" or "sha256"
	return &Session{cookies.New(), mng}, nil
}
