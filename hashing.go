package bperm

import "golang.org/x/crypto/bcrypt"

// Hash the password with bcrypt
func hashBcrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// Check if a given password is correct, for a given bcrypt hash
func correctBcrypt(hash string, password string) bool {
	// prevents timing attack
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
