package main

// Import our dependencies. We'll use the standard HTTP library as well as the gorilla router for this app
import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

type Response struct {
	Message string `json:"message"`
}

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

/* Apps type */
type App struct {
	Id          int
	Name        string
	Description string
}

var apps = []App{
	App{Id: 1, Name: "App 1", Description: "App 1 description"},
	App{Id: 2, Name: "App 2", Description: "App 2 description"},
	App{Id: 3, Name: "App 3", Description: "App 3 description"},
}

func main() {

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			// Verify 'aud' claim
			aud := os.Getenv("RBAC_API_ID")
			domain := os.Getenv("RBAC_DOMAIN")
			checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
			if !checkAud {
				return token, errors.New("Invalid audience.")
			}
			// Verify 'iss' claim
			iss := "https://" + domain + "/"
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
			if !checkIss {
				return token, errors.New("Invalid issuer.")
			}

			cert, err := getPemCert(token)
			if err != nil {
				panic(err.Error())
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		},
		SigningMethod: jwt.SigningMethodRS256,
	})

	r := mux.NewRouter()

	r.Handle("/apps", jwtMiddleware.Handler(AppsHandler)).Methods("GET")

	// For dev only - Set up CORS so React client can consume our API
	corsWrapper := cors.New(cors.Options{
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Content-Type", "Origin", "Accept", "*"},
	})

	http.ListenAndServe(":8080", corsWrapper.Handler(r))
}

var AppsHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	payload, _ := json.Marshal(apps)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(payload))
})

func getPemCert(token *jwt.Token) (string, error) {

	cert := ""
	domain := os.Getenv("RBAC_DOMAIN")
	resp, err := http.Get("https://" + domain + "/.well-known/jwks.json")

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k, _ := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("Unable to find appropriate key.")
		return cert, err
	}

	return cert, nil
}
