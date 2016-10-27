// Package permissionbolt provides middleware for keeping track of users,
// login states and permissions.
package bperm

import (
	"net/http"
	"strings"
)

type Paths string

const (
	aPaths Paths = "AdminPaths"
	uPaths Paths = "UserPaths"
	pPaths Paths = "PubblicPaths"
)

// The Permissions structure keeps track of the permissions for various path prefixes
type Permissions struct {
	state        *UserState
	paths        map[Paths][]string
	rootIsPublic bool
	denied       http.HandlerFunc
}

const (
	// Version number. Stable API within major version numbers.
	Version = 2.0
)

// New initializes a Permissions struct with all the default settings.
func New() (*Permissions, error) {
	state, err := NewUserStateSimple()
	if err != nil {
		return nil, err
	}
	return NewFromUserState(state), nil
}

// NewWithConf initializes a Permissions struct with a database filename
func NewWithConf(filename string) (*Permissions, error) {
	state, err := NewUserState(filename, true)
	if err != nil {
		return nil, err
	}
	return NewFromUserState(state), nil

}

// NewPermissions initializes a Permissions struct with the given UserState and
// a few default paths for admin/user/public path prefixes.
func NewFromUserState(state *UserState) *Permissions {
	paths := map[Paths][]string{}
	paths[aPaths] = []string{"/admin"}
	paths[uPaths] = []string{"/profiles", "/data"}
	paths[pPaths] = []string{
		"/", "/login", "/register",
		"/favicon.ico", "/style",
		"/img", "/js", "/favicon.ico",
		"/robots.txt", "/sitemap_index.xml",
	}

	return &Permissions{state,
		paths,
		true,
		DefaultDenyFunc}
}

// SetDenyFunction specifies a http.HandlerFunc for when the permissions are denied
func (perm *Permissions) SetDenyFunc(f http.HandlerFunc) {
	perm.denied = f
}

// DenyFunction returns the currently configured http.HandlerFunc for when
// permissions are denied
func (perm *Permissions) GetDenyFunc() http.HandlerFunc {
	return perm.denied
}

// default deny HandlerFunc
func DefaultDenyFunc(w http.ResponseWriter, req *http.Request) {
	http.Error(w, "Permission denied.", http.StatusForbidden)
}

// UserState retrieves the UserState struct
func (perm *Permissions) GetUserState() *UserState {
	return perm.state
}

// Clear sets every permission to public
func (perm *Permissions) Reset() {
	perm.paths[aPaths] = []string{}
	perm.paths[uPaths] = []string{}
}

// AddPublicPath adds an URL path prefix for pages that are public
func (perm *Permissions) AddPath(valid Paths, prefix string) {
	perm.paths[valid] = append(perm.paths[valid], prefix)
}

// SetAdminPath sets all URL path prefixes for pages that are only accessible
// for logged in administrators
func (perm *Permissions) SetPath(valid Paths, pathPrefixes []string) {
	perm.paths[valid] = pathPrefixes
}

// Rejected checks if a given http request should be rejected
func (perm *Permissions) Rejected(w http.ResponseWriter, req *http.Request) bool {
	var (
		reject = false
		path   = req.URL.Path // the path of the url that the user wish to visit
	)
	// If it's not "/" and set to be public regardless of permissions
	if !(perm.rootIsPublic && path == "/") {
		// Reject if it is an admin page and user is not an admin
		for _, prefix := range perm.paths[aPaths] {
			if strings.HasPrefix(path, prefix) {
				if !perm.state.AdminRights(req) {
					reject = true
					break
				}
			}
		}
		if !reject {
			// Reject if it's a user page and the user doesn't have perm
			for _, prefix := range perm.paths[uPaths] {
				if strings.HasPrefix(path, prefix) {
					if !perm.state.UserRights(req) {
						reject = true
						break
					}
				}
			}
		}
		if !reject {
			// Reject if it's not a public page
			found := false
			for _, prefix := range perm.paths[pPaths] {
				if strings.HasPrefix(path, prefix) {
					found = true
					break
				}
			}
			if !found {
				reject = true
			}
		}
	}
	return reject
}

// Middleware handler (compatible with Negroni)
func (perm *Permissions) ServeHTTP(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	// Check if the user has the right admin/user rights
	if perm.Rejected(w, req) {
		// Get and call the Permission Denied function
		perm.GetDenyFunc()(w, req)
		// Reject the request by not calling the next handler below
		return
	}
	// Call the next middleware handler
	next(w, req)
}
