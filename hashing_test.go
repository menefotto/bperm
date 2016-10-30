package bperm

import "testing"

func TesthashBcrypt(t *testing.T) {
	_, err := HashBcrypt("1235")
	if err != nil {
		t.Fatal("Ops somthing went wrong not hashed\n")
	}
}

func TestcorrectBcrypt(t *testing.T) {
	pass := "1235"
	hash, err := HashBcrypt("1235")
	if err != nil {
		t.Fatal("Ops somthing went wrong not hashed\n")
	}

	ok := correctBcrypt(hash, pass)
	if !ok {
		t.Fatal("Passwords should be the same")
	}
}
