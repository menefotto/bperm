package bperm

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bperm/randomstring"
	"golang.org/x/crypto/bcrypt"
)

// Hash the password with bcrypt
func HashBcrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// Check if a given password is correct, for a given bcrypt hash
func correctBcrypt(hash string, password string) bool {
	// prevents timing attack
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
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
