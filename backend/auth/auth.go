package auth

import (
	"log"
	"net/http"
	"strings"
	"time"

	"../dbhelper"
	"github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
)

var jwtSigningKey []byte

// SetJWTSecret sets the secret from config
func SetJWTSecret(jwtSecret string) {
	jwtSigningKey = []byte(jwtSecret)
}

// Register - POST /auth/register, PUT /auth/register
// Params:
// - username: nonempty nonoccupied username
// - password: nonempty string
// Returns:
// Status code 200 on success
func Register(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	missing := make([]string, 0, 2)
	usernameValues, ok := r.PostForm["username"]
	if !ok {
		missing = append(missing, "username")
	}
	passwordValues, ok := r.PostForm["password"]
	if !ok {
		missing = append(missing, "password")
	}
	if len(missing) > 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing fields: " + strings.Join(missing, ", ")))
		return
	}

	incorrect := make([]string, 0, 2)
	username := strings.Trim(usernameValues[0], " \t")
	if len(username) == 0 {
		incorrect = append(incorrect, "username")
	}
	password := passwordValues[0]
	if len(password) == 0 {
		incorrect = append(incorrect, "password")
	}
	if len(incorrect) > 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("incorrect fields: " + strings.Join(incorrect, ", ")))
		return
	}

	usernameStatus, err := dbhelper.CheckUsernameStatus(username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("can not check username status: %v", err.Error())
		return
	}
	if !usernameStatus {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("username is already taken"))
		return
	}

	if err = dbhelper.CreateUser(username, password); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("can not create user: %v", err.Error())
		return
	}
}

// Login - POST /auth/login
// Params:
// - username: nonempty string
// - password: nonempty string
// - remember_me (optional): true, or anything else
// Returns:
// - JWT token on success, status code 401 on incorrect credentials
// Implementation is based on https://auth0.com/blog/authentication-in-golang/
func Login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	missing := make([]string, 0, 2)
	usernameValues, ok := r.PostForm["username"]
	if !ok {
		missing = append(missing, "username")
	}
	passwordValues, ok := r.PostForm["password"]
	if !ok {
		missing = append(missing, "password")
	}
	if len(missing) > 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing fields: " + strings.Join(missing, ", ")))
		return
	}

	incorrect := make([]string, 0, 2)
	username := strings.Trim(usernameValues[0], " \t")
	if len(username) == 0 {
		incorrect = append(incorrect, "username")
	}
	password := passwordValues[0]
	if len(password) == 0 {
		incorrect = append(incorrect, "password")
	}
	if len(incorrect) > 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("incorrect fields: " + strings.Join(incorrect, ", ")))
		return
	}

	user, err := dbhelper.FindUserByUsername(username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	hash, err := dbhelper.ComputePasswordHash(password, user.Salt)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("can not compute hash to test equality: %v", err.Error())
		return
	}
	if hash != user.PasswordHash {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// authenticated user, return token

	// create token
	token := jwt.New(jwt.SigningMethodHS256)

	// calculate expiration time
	var expirationTime int64
	if rememberMe, ok := r.PostForm["remember_me"]; ok && rememberMe[0] == "true" {
		expirationTime = time.Now().Add(time.Hour * 16).Unix()
	} else {
		expirationTime = time.Now().Add(time.Hour * 24 * 10).Unix()
	}

	// set-up claims
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = user.ID
	claims["username"] = user.Username
	claims["exp"] = expirationTime

	// sign the token
	tokenString, _ := token.SignedString(jwtSigningKey)

	w.Write([]byte(tokenString))
}

// TokenStatus - GET /auth/token-status, authenticated
// Returns:
// Status code 200 on valid token, 401 on invalid token
func TokenStatus(w http.ResponseWriter, r *http.Request) {
	// token is not being refreshed, do nothing here
}

// ChangeUsername - POST /auth/change-username, authenticated
// Params:
// - username: nonempty nonoccupied username
// Returns:
// Status code 200 on success
func ChangeUsername(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	r.ParseForm()

	usernameValues, ok := r.PostForm["username"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing field username"))
		return
	}

	username := strings.Trim(usernameValues[0], " \t")
	if len(username) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("incorrect field username"))
		return
	}

	user, err := dbhelper.FindUser(userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("can not check whether user exists: %v", err.Error())
		return
	}
	if user == nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("user does not exist"))
		return
	} else if user.Username == username {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("username is identical to current"))
		return
	}

	usernameStatus, err := dbhelper.CheckUsernameStatus(username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("can not check username status: %v", err.Error())
		return
	}
	if !usernameStatus {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("username is already taken"))
		return
	}

	if err = dbhelper.ChangeUsername(userID, username); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("can not change username: %v", err.Error())
		return
	}
}

// UsernameStatus - GET /auth/username-status
// Params:
// - username: nonempty string
// Returns:
// - either "free" or "occupied"
func UsernameStatus(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	usernameValues, ok := r.Form["username"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing field username"))
		return
	}
	username := strings.Trim(usernameValues[0], " \t")
	if len(username) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("incorrect field username"))
		return
	}

	status, err := dbhelper.CheckUsernameStatus(username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("can not check username status: %v", err.Error())
		return
	}

	if status {
		w.Write([]byte("free"))
	} else {
		w.Write([]byte("occupied"))
	}
}

// ChangePassword - POST /auth/change-password, authenticated
// Params:
// - password: nonempty string
// Returns:
// Status code 200 on success
func ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	r.ParseForm()

	usernameValues, ok := r.PostForm["password"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing field password"))
		return
	}

	password := usernameValues[0]
	if len(password) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("incorrect field password"))
		return
	}

	user, err := dbhelper.FindUser(userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("can not check whether user exists: %v", err.Error())
		return
	}
	if user == nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("user does not exist"))
		return
	}

	if err = dbhelper.ChangePassword(userID, password); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("can not change password: %v", err.Error())
		return
	}
}

// JwtMiddleware generates wrapping handlers for route authentiation
var JwtMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
		return jwtSigningKey, nil
	},
	// UserProperty: "user",	// user is default, it can be accessed through r.Context()
	SigningMethod: jwt.SigningMethodHS256,
})

func getUserID(r *http.Request) int {
	token := r.Context().Value("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)
	return int(claims["user_id"].(float64))
}
