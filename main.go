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
	sessionName    = "example-google-app"
	sessionSecret  = "example cookie signing secret"
	sessionUserKey = "googleID"
)

// sessionStore encodes and decodes session data stored in signed cookies
var store = sessions.NewCookieStore([]byte(sessionSecret), nil)

var views = template.Must(template.ParseGlob("templates/*.html"))

func routeLog(r *http.Request) *log.Entry {
	l := log.WithFields(log.Fields{
		"id": r.Header.Get("X-Request-Id"),
		"ua": r.UserAgent(),
	})
	return l
}

// New returns a new ServeMux with app routes.
func New() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", welcomeHandler)
	mux.Handle("/profile", requireLogin(http.HandlerFunc(profileHandler)))
	mux.HandleFunc("/logout", logoutHandler)
	// 1. Register LoginHandler and CallbackHandler
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

func issueSession() http.Handler {
	log.Info("issueSession")
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
		session.Values[sessionUserKey] = googleUser.Id
		err = session.Save(req, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, req, "/profile", http.StatusFound)
	}
	return http.HandlerFunc(fn)
}

func welcomeHandler(w http.ResponseWriter, req *http.Request) {
	log := routeLog(req)
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	if isAuthenticated(req) {
		log.Info("authenticated")
		http.Redirect(w, req, "/profile", http.StatusFound)
		return
	}
	log.Warn("unauthenticated")
	views.ExecuteTemplate(w, "home.html", nil)
}

// profileHandler shows protected user content.
func profileHandler(w http.ResponseWriter, req *http.Request) {
	log := routeLog(req)
	session, err := store.Get(req, sessionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Infof("profile, session: %#v", session.Values)
	views.ExecuteTemplate(w, "profile.html", session.Values)

}

// logoutHandler destroys the session on POSTs and redirects to home.
func logoutHandler(w http.ResponseWriter, req *http.Request) {
	log := routeLog(req)
	if req.Method == "POST" {
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
		if !isAuthenticated(req) {
			http.Redirect(w, req, "/", http.StatusFound)
			return
		}
		next.ServeHTTP(w, req)
	}
	return http.HandlerFunc(fn)
}

func isAuthenticated(req *http.Request) bool {
	log := routeLog(req)
	session, err := store.Get(req, sessionName)
	if err != nil {
		log.WithError(err).Fatal("failed to retrieve session")
		return false
	}
	log.Infof("Session: %#v", session)
	// Q: If user id is set, we consider the person as logged in!?
	// A: It can only be set via signed cookie, so probably OK
	_, ok := session.Values[sessionUserKey]
	return ok
}

// main creates and starts a Server listening.
func main() {
	log.SetHandler(jsonhandler.Default)
	err := http.ListenAndServe(":"+os.Getenv("PORT"), New())
	if err != nil {
		log.WithError(err).Fatal("error listening")
	}
}
