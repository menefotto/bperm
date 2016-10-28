package bperm

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// ErrBcrypt happends with bcryt fails to hash...
var ErrBcrypt = errors.New("Bpermission: bcrypt could not hash the passwd")

// Hash the password with bcrypt
func hashBcrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", ErrBcrypt
	}
	return string(hash), nil
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
