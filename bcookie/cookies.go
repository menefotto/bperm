package bcookie

// Thanks to web.go (https://github.com/hoisie/web) for several of these functions

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Secure interface {
	Get(r *http.Request, name, cookieSecret string) (string, bool)
	SetPath(w http.ResponseWriter, name, val string, age int64, path string, cookieSecret string) error
	Del(w http.ResponseWriter, cookieName, cookiePath string)
}

const (
	Version           = 1.0
	DefaultCookieTime = 3600 * 24 // Login cookies should last for 24 hours, by default
)

// Get a secure cookie from a HTTP request
func Get(req *http.Request, name string, cookieSecret string) (string, bool) {
	cookie, err := req.Cookie(name)
	if err != nil {
		return "", false
	}

	parts := strings.SplitN(cookie.Value, "|", 3)
	if len(parts) != 3 {
		return "", false
	}

	val, timestamp, sig := parts[0], parts[1], parts[2]

	if getSignature(cookieSecret, []byte(val), timestamp) != sig {
		return "", false
	}

	ts, _ := strconv.ParseInt(timestamp, 0, 64)
	if time.Now().Unix()-31*86400 > ts {
		return "", false
	}

	decoded, err := decodeBase64(val)
	if err != nil {
		return "", false
	}

	return string(decoded), true
}

// Set a secure cookie with an explicit path.
// age is the time-to-live, in seconds (0 means forever).
func SetPath(w http.ResponseWriter, name, val string, age int64, path string, cookieSecret string) error {
	var (
		buf     bytes.Buffer
		utctime time.Time
	)

	if len(cookieSecret) == 0 {
		return http.ErrNoCookie
	}

	encodeBase64(&buf, val)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	sig := getSignature(cookieSecret, buf.Bytes(), timestamp)
	cookieVal := strings.Join([]string{buf.String(), timestamp, sig}, "|")

	if age == 0 {
		utctime = time.Unix(2147483647, 0) // 2^31 - 1 seconds (roughly 2038)
	} else {
		utctime = time.Unix(time.Now().Unix()+age, 0)
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

// Clear the given cookie name, with a corresponding path
// Note that browsers *may* be configured to not delete the cookie.
func Del(w http.ResponseWriter, cookieName, cookiePath string) {
	ignoredContent := "BLUBLU" // random string

	cookieStr := "%s=%s; path=%s; expires=Thu, 01 Jan 1970 00:00:00 GMT"
	cookie := fmt.Sprintf(cookieStr, cookieName, ignoredContent, cookiePath)

	w.Header().Set("Set-Cookie", cookie)
}

// Get the cookie signature
func getSignature(key string, val []byte, timestamp string) string {
	hm := hmac.New(sha1.New, []byte(key))

	hm.Write(val)
	hm.Write([]byte(timestamp))

	hex := fmt.Sprintf("%02x", hm.Sum(nil))
	return hex
}

func encodeBase64(buf *bytes.Buffer, val string) {
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	encoder.Write([]byte(val))
	defer encoder.Close()
}

func decodeBase64(val string) ([]byte, error) {
	buf := bytes.NewBufferString(val)
	encoder := base64.NewDecoder(base64.StdEncoding, buf)

	return ioutil.ReadAll(encoder)
}
