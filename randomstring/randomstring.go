package randomstring

// Functions for generating random strings

import (
	"math/rand"
)

// Generate a random string of the given length.
func Gen(length int) string {
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = byte(rand.Int63() & 0xff)
	}
	return string(b)
}

// Generate a random, but cookie/human friendly, string of the given length.
func GenReadable(length int) string {
	const allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = allowed[rand.Intn(len(allowed))]
	}
	return string(b)
}
