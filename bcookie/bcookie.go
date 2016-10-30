package bcookie

// Thanks to web.go (https://github.com/hoisie/web) for several of these functions

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bperm/randomstring"
)

type SecureType interface {
	Get(r *http.Request, name string) (string, error)
	SetPath(w http.ResponseWriter, name, val string, path string) error
	Del(w http.ResponseWriter, cookieName, cookiePath string)
}

const (
	Version           = 1.0
	DefaultCookieTime = 3600 * 24 // Login cookies should last for 24 hours, by default
)

type Secure struct {
	ExpirationTime int64
	Secret         string
}

// New created a secure cookie with default 24 life
func New() *Secure {
	return &Secure{DefaultCookieTime, randomstring.GenReadable(32)}
}

// New created a secure cookie with optional cookie life specified in seconds
func NewWithExpirationTime(cookieExpirationTime int64) *Secure {
	return &Secure{DefaultCookieTime, randomstring.GenReadable(32)}
}

// Get a secure cookie from a HTTP request
func (s *Secure) Get(req *http.Request, name string) (string, error) {
	cookie, err := req.Cookie(name)
	if err != nil {
		return "", err
	}

	parts := strings.SplitN(cookie.Value, "|", 3)
	if len(parts) != 3 {
		return "", err
	}

	val, timestamp, sig := parts[0], parts[1], parts[2]

	if getSignature(s.Secret, []byte(val), timestamp) != sig {
		return "", err
	}

	ts, _ := strconv.ParseInt(timestamp, 0, 64)
	if time.Now().Unix()-31*86400 > ts {
		return "", err
	}

	decoded, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

// Del the given cookie name, with a corresponding path
// Note that browsers *may* be configured to not delete the cookie.
func (s *Secure) Del(w http.ResponseWriter, cookieName, cookiePath string) {
	ignoredContent := "BLUBLU" // random string

	cookieStr := "%s=%s; path=%s; expires=Thu, 01 Jan 1970 00:00:00 GMT"
	cookie := fmt.Sprintf(cookieStr, cookieName, ignoredContent, cookiePath)

	w.Header().Set("Set-Cookie", cookie)
}

// SetPath a secure cookie with an explicit path.
// age is the time-to-live, in seconds (0 means forever).
func (s *Secure) SetPath(w http.ResponseWriter, name, val string, path string) error {

	var (
		utctime time.Time
		encoded string
	)

	if len(s.Secret) == 0 {
		return errors.New("Cookie secret not valid\n")
	}

	encoded = base64.StdEncoding.EncodeToString([]byte(val))

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	sig := getSignature(s.Secret, []byte(encoded), timestamp)
	cookieVal := strings.Join([]string{encoded, timestamp, sig}, "|")

	if s.ExpirationTime == 0 {
		utctime = time.Unix(2147483647, 0) // 2^31 - 1 seconds (roughly 2038)
	} else {
		utctime = time.Unix(time.Now().Unix()+s.ExpirationTime, 0)
	}

	cookie := http.Cookie{
		Name:    name,
		Value:   cookieVal,
		Expires: utctime,
		Path:    path,
	}

	w.Header().Add("Set-Cookie", cookie.String())

	return nil
}

// getSignature the cookie signature
func getSignature(key string, val []byte, timestamp string) string {
	hm := hmac.New(sha1.New, []byte(key))

	hm.Write(val)
	hm.Write([]byte(timestamp))

	hex := fmt.Sprintf("%02x", hm.Sum(nil))
	return hex
}
