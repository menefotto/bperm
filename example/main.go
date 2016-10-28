package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/bperm"
	"github.com/bperm/backend"
	"github.com/codegangsta/negroni"
)

func main() {
	n := negroni.Classic()
	mux := http.NewServeMux()

	// New permissions middleware
	perm, err := bperm.New()
	if err != nil {
		log.Fatalln(err)
	}

	// Blank slate, no default permissions
	//perm.Clear()
	user := &backend.User{}
	user.Name = "bob"
	user.Username = "hunter1"
	user.Email = "bob@zombo.com"

	// Get the userstate, used in the handlers below
	userstate := perm.GetUserState()

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		user, err := userstate.GetUser("bob")
		if err != nil {
			fmt.Fprintf(w, "Users is not registered\n")
		} else {
			fmt.Fprintf(w, "Has user bob: %v\n", true)
			fmt.Fprintf(w, "User is active: %v\n", user.Active)
			fmt.Fprintf(w, "Logged in on server: %v\n", user.Loggedin)
			fmt.Fprintf(w, "Is confirmed: %v\n", user.Confirmed)
			fmt.Fprintf(w, "Username stored in cookies (or blank): %v\n", user.Username)

		}

		fmt.Fprintf(w, "Current user is logged in, has a valid cookie and *admin rights*: %v\n", userstate.IsCurrentUserAdmin(req))
		fmt.Fprintf(w, "\nTry: /register, /confirm, /remove, /login, /logout, /makeadmin, /clear, /data and /admin")
	})

	mux.HandleFunc("/register", func(w http.ResponseWriter, req *http.Request) {
		err := userstate.AddUser(user)
		if err != nil {
			fmt.Fprintf(w, "failed to register user err: %v\n", err)
			return
		}

		val, err := userstate.GetUserStatus("bob", bperm.Username)
		if err != nil {
			fmt.Fprintf(w, "Err getting user status %v\n", err)
			return
		}

		fmt.Fprintf(w, "User bob was created: %v\n", val.(string))
	})

	mux.HandleFunc("/confirm", func(w http.ResponseWriter, req *http.Request) {
		userstate.SetUserStatus("bob", bperm.Confirmed, true)
		val, _ := userstate.GetUserStatus("bob", bperm.Confirmed)
		fmt.Fprintf(w, "User bob was confirmed: %v\n", val.(bool))
	})

	mux.HandleFunc("/remove", func(w http.ResponseWriter, req *http.Request) {
		_ = userstate.SetUserStatus("bob", bperm.Active, false)
		val, _ := userstate.GetUserStatus("bob", bperm.Active)
		fmt.Fprintf(w, "User bob is active: %v\n", val.(bool))
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, req *http.Request) {
		userstate.Login(w, "bob")
		val, _ := userstate.GetUserStatus("bob", bperm.Loggedin)
		fmt.Fprintf(w, "bob is now logged in: %v\n", val.(bool))
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, req *http.Request) {
		userstate.Logout("bob")
		val, _ := userstate.GetUserStatus("bob", bperm.Loggedin)
		fmt.Fprintf(w, "bob is now logged out: %v\n", !val.(bool))
	})

	mux.HandleFunc("/makeadmin", func(w http.ResponseWriter, req *http.Request) {
		userstate.SetUserStatus("bob", bperm.Admin, true)
		val, _ := userstate.GetUserStatus("bob", bperm.Admin)
		fmt.Fprintf(w, "bob is now administrator: %v\n", val.(bool))
	})

	mux.HandleFunc("/clear", func(w http.ResponseWriter, req *http.Request) {
		userstate.ClearCookie(w)
		fmt.Fprintf(w, "Cleared cookie")
	})

	mux.HandleFunc("/data", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "user page that only logged in users must see!")
	})

	mux.HandleFunc("/admin", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "super secret information that only logged in administrators must see!\n\n")
		if usernames, err := userstate.GetAll("Username"); err == nil {
			fmt.Fprintf(w, "list of all users: "+strings.Join(usernames, ", "))
		}
	})

	// Custom handler for when permissions are denied
	perm.SetDenyFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "Permission denied!", http.StatusForbidden)
	})

	// Enable the permissions middleware
	n.Use(perm)

	// Use mux for routing, this goes last
	n.UseHandler(mux)

	// Serve
	n.Run(":3000")
}
