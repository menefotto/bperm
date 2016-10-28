package bperm

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNew(t *testing.T) {
	_, err := New()
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewWithConf(t *testing.T) {
	_, err := NewWithConf("whatever")
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetSetDenyFunc(t *testing.T) {
	perms, err := New()
	if err != nil {
		t.Fatal(err)
	}

	perms.SetDenyFunc(DefaultDenyFunc)
	_ = perms.GetDenyFunc()
}

func TestGetUserState(t *testing.T) {
	perms, err := New()
	if err != nil {
		t.Fatal(err)
	}
	userState := perms.GetUserState()
	if userState == nil {
		t.Fatal("Ops something went wrong should not be nil\n")
	}
}

func TestAddPath(t *testing.T) {
	perms, err := New()
	if err != nil {
		t.Fatal(err)
	}

	var ok bool
	perms.AddPath(aPaths, "/test")
	for _, v := range perms.paths[aPaths] {
		if v == "/test" {
			ok = true
		}
	}

	if !ok {
		t.Fatal("AddPath failed\n")
	}
}

func TestSetPath(t *testing.T) {
	perms, err := New()
	if err != nil {
		t.Fatal(err)
	}

	perms.SetPath(aPaths, []string{"/test"})
	path := perms.paths[aPaths]
	if path[0] != "/test" {
		t.Fatal("Set path failed")
	}
}

func TestReset(t *testing.T) {
	perms, err := New()
	if err != nil {
		t.Fatal(err)
	}

	perms.Reset()
	if len(perms.paths[aPaths]) != 0 || len(perms.paths[uPaths]) != 0 {
		t.Fatal("Something went wrong paths not reseted\n")
	}
}

func TestRejected(t *testing.T) {
	perms, err := New()
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	root, _ := http.NewRequest("GET", "/", nil)
	admin, _ := http.NewRequest("GET", "/admin", nil)
	data, _ := http.NewRequest("GET", "/data", nil)
	ok := perms.Rejected(w, root)
	if ok {
		t.Fatal("should have been rejectet\n")
	}
	ok = perms.Rejected(w, admin)
	if !ok {
		t.Fatal("should have been rejectet\n")
	}
	ok = perms.Rejected(w, data)
	if ok {
		t.Fatal("should have been rejectet\n")
	}
}

func TestServeHttpReject(t *testing.T) {
	perms, err := New()
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	root, _ := http.NewRequest("GET", "/", nil)
	//admin, _ := http.NewRequest("GET", "/admin", nil)
	perms.ServeHTTP(w, root, DefaultDenyFunc)

}

func TestServeHttpNoReject(t *testing.T) {
	perms, err := New()
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	admin, _ := http.NewRequest("GET", "/admin", nil)
	perms.ServeHTTP(w, admin, DefaultDenyFunc)

}
