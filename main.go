package main

import (
	"fmt"
	"html/template"
	"net/http"
	"os"

	"github.com/apex/log"
	jsonhandler "github.com/apex/log/handlers/json"
	"github.com/dghubble/gologin"
	"github.com/dghubble/gologin/google"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	googleOAuth2 "golang.org/x/oauth2/google"
)

const (
	sessionName = "internal-google-login"
	// Q: Should I be using https://github.com/gorilla/securecookie instead?
	sessionSecret = "example cookie signing secret"
)

// sessionStore encodes and decodes session data stored in signed cookies
var store = sessions.NewCookieStore([]byte(sessionSecret), nil)
var views = template.Must(template.ParseGlob("templates/*.html"))

func routeLog(r *http.Request) *log.Entry {
	l := log.WithFields(log.Fields{
		"id":   r.Header.Get("X-Request-Id"),
		"auth": isAuthenticated(r),
	})
	return l
}

// New describes the routes
func New() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.Handle("/admin", requireLogin(http.HandlerFunc(adminHandler)))
	mux.HandleFunc("/logout", logoutHandler)

	oauth2Config := &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  fmt.Sprintf("https://%s/google/callback", os.Getenv("DOMAIN")),
		Endpoint:     googleOAuth2.Endpoint,
		Scopes:       []string{"profile", "email"},
	}

	// Don't quite understand this, could also be gologin.DebugOnlyCookieConfig
	stateConfig := gologin.DefaultCookieConfig
	mux.Handle("/google/login", google.StateHandler(stateConfig, google.LoginHandler(oauth2Config, nil)))
	mux.Handle("/google/callback", google.StateHandler(stateConfig, google.CallbackHandler(oauth2Config, issueSession(), nil)))
	return mux
}

// issueSessions sets the signed cookie and redirects to /admin page
func issueSession() http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		googleUser, err := google.UserFromContext(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session, _ := store.Get(req, sessionName)
		store.Options.HttpOnly = true
		store.Options.Secure = true

		log.Debugf("issueSession: %#v", googleUser)

		session.Values["ID"] = googleUser.Id
		session.Values["Name"] = googleUser.Name

		err = session.Save(req, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, req, "/admin", http.StatusFound)
	}
	return http.HandlerFunc(fn)
}

func indexHandler(w http.ResponseWriter, req *http.Request) {
	log := routeLog(req)
	log.Info("index")
	err := views.ExecuteTemplate(w, "index.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// adminHandler is for the admin only
func adminHandler(w http.ResponseWriter, req *http.Request) {
	log := routeLog(req)
	session, err := store.Get(req, sessionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Debugf("profile, session: %#v", session.Values)

	// TODO: Could we get this info into header.html?

	err = views.ExecuteTemplate(w, "admin.html", session.Values)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// logoutHandler kills the cookie
func logoutHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		log := routeLog(req)
		session, err := store.Get(req, sessionName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session.Options.MaxAge = -1
		err = session.Save(req, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Info("deleting cookie")
	}
	http.Redirect(w, req, "/", http.StatusFound)
}

func requireLogin(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		gAuth := isAuthenticated(req)
		if gAuth == "" {
			http.Redirect(w, req, "/google/login", http.StatusFound)
			return
		}
		if gAuth == "100571906555529103327" {
			log.Info("Kai is logging in")
		} else {
			log.Infof("Who is %#v", gAuth)
		}
		next.ServeHTTP(w, req)
	}
	return http.HandlerFunc(fn)
}

func isAuthenticated(req *http.Request) string {
	session, err := store.Get(req, sessionName)
	if err != nil {
		log.WithError(err).Fatal("failed to retrieve session")
		return ""
	}
	// Q: If user id is set, we consider the person as logged in!?
	// A: It can only be set via signed cookie, so probably OK
	ID, ok := session.Values["ID"].(string)
	log.Infof("ID is %v", ID)
	if !ok {
		return ""
	}
	return ID
}

// main creates and starts a Server listening.
func main() {
	log.SetHandler(jsonhandler.Default)
	err := http.ListenAndServe(":"+os.Getenv("PORT"), New())
	if err != nil {
		log.WithError(err).Fatal("error listening")
	}
}
