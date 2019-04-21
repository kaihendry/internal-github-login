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
	session, err := store.Get(r, sessionName)
	if err == nil {
		mapString := make(map[string]string)
		// https://stackoverflow.com/a/48226206/4534
		for key, value := range session.Values {
			strKey := fmt.Sprintf("%v", key)
			strValue := fmt.Sprintf("%v", value)
			mapString[strKey] = strValue
		}
		return log.WithFields(log.Fields{
			"id":   r.Header.Get("X-Request-Id"),
			"auth": mapString,
		})
	}
	return log.WithFields(log.Fields{
		"id": r.Header.Get("X-Request-Id"),
	})
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
// upon successful Google authentication
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
		session, err := store.Get(req, sessionName)
		// If ID is nil, we assume no Google auth has been performed
		if err != nil || session.Values["ID"] == nil {
			http.Redirect(w, req, "/google/login", http.StatusFound)
			return
		}
		if session.Values["ID"] == "100571906555529103327" {
			log.Info("lets not let Kai in as an Admin")
			http.Error(w, fmt.Sprintf("Sorry %s, you are not allowed as an administrator.", session.Values["Name"]), 401)
			return
		} else {
			log.Infof("Who is %#v ?", session.Values["Name"])
		}
		next.ServeHTTP(w, req)
	}
	return http.HandlerFunc(fn)
}

func main() {
	log.SetHandler(jsonhandler.Default)
	err := http.ListenAndServe(":"+os.Getenv("PORT"), New())
	if err != nil {
		log.WithError(err).Fatal("error listening")
	}
}
