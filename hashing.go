package bperm

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"

	"io"

	"golang.org/x/crypto/bcrypt"
)

var ErrBcrypt = errors.New("Bpermission: bcrypt could not hash the passwd")

// Hash the password with sha256 (the username is needed for salting)
func hashSha256(cookieSecret, username, password string) (string, error) {
	hasher := sha256.New()
	// Use the cookie secret as additional salt
	io.WriteString(hasher, password+cookieSecret+username)

	return string(hasher.Sum(nil)), nil
}

// Hash the password with bcrypt
func hashBcrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", ErrBcrypt
	}
	return string(hash), nil
}

// Check if a given password(+username) is correct, for a given sha256 hash
func correctSha256(hash []byte, cookieSecret, username, password string) bool {
	comparisonHash, _ := hashSha256(cookieSecret, username, password)
	// check that the lengths are equal before calling ConstantTimeCompare
	if len(hash) != len([]byte(comparisonHash)) {
		return false
	}
	// prevents timing attack
	return subtle.ConstantTimeCompare(hash, []byte(comparisonHash)) == 1
}

// Check if a given password is correct, for a given bcrypt hash
func correctBcrypt(hash []byte, password string) bool {
	// prevents timing attack
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

// Check if the given hash is sha256 (when the alternative is only bcrypt)
func isSha256(hash []byte) bool {
	return len(hash) == 32
}
