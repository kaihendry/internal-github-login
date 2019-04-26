package main

import (
	"fmt"
	"html/template"
	"net/http"
	"os"

	"github.com/apex/log"
	jsonhandler "github.com/apex/log/handlers/json"
	texthandler "github.com/apex/log/handlers/text"
	"github.com/dghubble/gologin"
	"github.com/dghubble/gologin/google"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	googleOAuth2 "golang.org/x/oauth2/google"
)

const sessionName = "internal-google-login"

// sessionStore encodes and decodes session data stored in signed cookies

// var store = sessions.NewFilesystemStore("foobar", []byte(os.Getenv("SESSION_SECRET")))
var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")), nil)

var views = template.Must(template.ParseGlob("templates/*.html"))

func main() {
	if os.Getenv("UP_STAGE") != "" {
		log.SetHandler(jsonhandler.Default)
	} else {
		log.SetHandler(texthandler.Default)
	}
	err := http.ListenAndServe(":"+os.Getenv("PORT"), BasicEngine())
	if err != nil {
		log.WithError(err).Fatal("error listening")
	}
}

// BasicEngine sets up the routes
func BasicEngine() http.Handler {
	app := mux.NewRouter()
	app.HandleFunc("/", indexHandler)
	app.Handle("/admin", requireLogin(http.HandlerFunc(adminHandler)))
	app.HandleFunc("/logout", logoutHandler)

	// Setup for local development with gin
	redirectURL := "http://localhost:3000/google/callback"
	stateConfig := gologin.DebugOnlyCookieConfig
	// When deployed with UP
	if os.Getenv("UP_STAGE") != "" {
		redirectURL = fmt.Sprintf("https://%s/google/callback", os.Getenv("DOMAIN"))
		stateConfig = gologin.DefaultCookieConfig
	}

	oauth2Config := &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  redirectURL,
		Endpoint:     googleOAuth2.Endpoint,
		Scopes:       []string{"profile", "email"},
	}

	app.Handle("/google/login", google.StateHandler(stateConfig, google.LoginHandler(oauth2Config, nil)))
	app.Handle("/google/callback", google.StateHandler(stateConfig, google.CallbackHandler(oauth2Config, issueSession(), nil)))
	return app
}

func logWithContext(r *http.Request) *log.Entry {
	logs := log.WithField("", "")
	if os.Getenv("UP_STAGE") != "" {
		logs = log.WithFields(log.Fields{
			"id": r.Header.Get("X-Request-Id"),
		})
	}
	session, err := store.Get(r, sessionName)
	if err == nil {
		mapString := make(map[string]string)
		// https://stackoverflow.com/a/48226206/4534
		for key, value := range session.Values {
			strKey := fmt.Sprintf("%v", key)
			strValue := fmt.Sprintf("%v", value)
			mapString[strKey] = strValue
		}
		return logs.WithFields(log.Fields{
			"auth": mapString,
		})
	}
	return logs
}

// issueSession sets the signed cookie and redirects to /admin page
// upon successful Google authentication
func issueSession() http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		googleUser, err := google.UserFromContext(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session, err := store.Get(req, sessionName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		store.Options.HttpOnly = true

		if os.Getenv("UP_STAGE") != "" {
			log.Info("setting secure cookie")
			store.Options.Secure = true
		}

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
	logs := logWithContext(req)
	session, err := store.Get(req, sessionName)
	if err != nil {
		log.WithError(err).Error("bad session")
		http.SetCookie(w, &http.Cookie{Name: sessionName, MaxAge: -1, Path: "/"})
	}
	logs.Info("index")
	err = views.ExecuteTemplate(w, "index.html", session.Values)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// adminHandler is for the admin only, requireLogin should be set in routes
func adminHandler(w http.ResponseWriter, req *http.Request) {
	logs := logWithContext(req)
	session, err := store.Get(req, sessionName)
	if err != nil {
		log.WithError(err).Error("bad session")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	logs.Debugf("profile, session: %#v", session.Values)
	logs.Info("admin")
	err = views.ExecuteTemplate(w, "admin.html", session.Values)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// logoutHandler kills the cookie
func logoutHandler(w http.ResponseWriter, req *http.Request) {
	logs := logWithContext(req)
	session, err := store.Get(req, sessionName)
	if err != nil {
		log.WithError(err).Error("unable to retrieve cookie")
	}
	session.Options.MaxAge = -1
	err = session.Save(req, w)
	if err != nil {
		log.WithError(err).Error("unable to remove cookie")
	}
	logs.Info("logout: deleted cookie")
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
		// if session.Values["ID"] == "100571906555529103327" {
		// 	log.Info("lets not let Kai in as an Admin")
		// 	http.Error(w, fmt.Sprintf("Sorry %s, you are not allowed as an administrator.", session.Values["Name"]), 401)
		// 	return
		// } else {
		// 	log.Infof("Who is %#v ?", session.Values["Name"])
		// }
		next.ServeHTTP(w, req)
	}
	return http.HandlerFunc(fn)
}
