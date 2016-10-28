package bcookie

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAndNewWithExpirationTime(t *testing.T) {
	_ = New()
	_ = NewWithExpirationTime(3600 * 24)
}

func TestGetSetPathOkCase(t *testing.T) {
	secret := "abracadabra"

	securecookie := New()
	w := httptest.NewRecorder()
	err := securecookie.SetPath(w, "user", "wind85", securecookie.CookieExpirationTime, "/", secret)
	if err != nil {
		t.Fatal(err)
	}

	req := &http.Request{Header: http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}}
	username, err := securecookie.Get(req, "user", secret)
	if err != nil {
		t.Fatal(err)
	}

	if username != "wind85" {
		t.Fatal("Something went wrong, user is  %s\n", username)
	}

}

func TestGetSetPathOkZeroTimeCase(t *testing.T) {
	secret := "abracadabra"

	securecookie := New()
	w := httptest.NewRecorder()
	err := securecookie.SetPath(w, "user", "wind85", 0, "/", secret)
	if err != nil {
		t.Fatal(err)
	}

	req := &http.Request{Header: http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}}
	username, err := securecookie.Get(req, "user", secret)
	if err != nil {
		t.Fatal(err)
	}

	if username != "wind85" {
		t.Fatal("Something went wrong, user is  %s\n", username)
	}

}

func TestGetSetPathNoValidSecretCase(t *testing.T) {
	secret := ""

	securecookie := New()
	w := httptest.NewRecorder()
	err := securecookie.SetPath(w, "user", "wind85", 0, "/", secret)
	if err == nil {
		t.Fatal("Should have got an error\n")
	}
}

func TestGetSetPathFailCase(t *testing.T) {
	secret := "abracadabra"

	securecookie := New()
	rec := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		err := securecookie.SetPath(w, "user", "wind85", securecookie.CookieExpirationTime, "/test", secret)
		if err != nil {
			t.Fatal(err)
		}
	})

	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatal(err)
	}
	_, err = securecookie.Get(req, "user", secret)
	if err == nil {
		t.Fatal("Should have not found the cookie\n")
	}

}

func TestDel(t *testing.T) {
	secret := "Abracadabra"

	securecookie := New()
	w := httptest.NewRecorder()
	err := securecookie.SetPath(w, "user", "wind85", securecookie.CookieExpirationTime, "/", secret)
	if err != nil {
		t.Fatal(err)
	}

	securecookie.Del(w, "user", "/")
	if w.HeaderMap["SetCookie"] != nil {
		t.Fatal("cookie not deleted")
	}
}
