package main

import (
	"log"
	"net/http"
	"time"

	"./auth"
	"./confhelper"
	"./dbhelper"
	"./encrypt"
	"./hashing"
	"./keygen"
	"./keys"

	_ "github.com/go-sql-driver/mysql"
	"github.com/rs/cors"
	"github.com/gorilla/mux"
)

func main() {
	// parse config
	dbConnectionString, jwtSecret, err := confhelper.ParseConfig("./config.json")
	if err != nil {
		log.Fatalf("can not parse \"./config.json\": %v", err.Error())
	}

	// initialize modules
	if err := dbhelper.InitializeDatabase(dbConnectionString); err != nil {
		log.Fatalf("can not connect to database: %v", err.Error())
	}
	auth.SetJWTSecret(jwtSecret)

	// register routes
	r := mux.NewRouter()

	// encrypt
	r.HandleFunc("/rsa/encrypt", encrypt.RSAEncrypt).Methods("POST")
	r.HandleFunc("/rsa/decrypt", encrypt.RSADecrypt).Methods("POST")
	r.HandleFunc("/aes/encrypt", encrypt.AESEncrypt).Methods("POST")
	r.HandleFunc("/aes/decrypt", encrypt.AESDecrypt).Methods("POST")
	r.HandleFunc("/blowfish/encrypt", encrypt.BlowfishEncrypt).Methods("POST")
	r.HandleFunc("/blowfish/decrypt", encrypt.BlowfishDecrypt).Methods("POST")
	r.HandleFunc("/twofish/encrypt", encrypt.TwofishEncrypt).Methods("POST")
	r.HandleFunc("/twofish/decrypt", encrypt.TwofishDecrypt).Methods("POST")

	// key and password generation
	r.HandleFunc("/rsa/key", keygen.RSAKey).Methods("GET")
	r.HandleFunc("/aes/key", keygen.AESKey).Methods("GET")
	r.HandleFunc("/blowfish/key", keygen.BlowfishKey).Methods("GET")
	r.HandleFunc("/twofish/key", keygen.TwofishKey).Methods("GET")
	r.HandleFunc("/password", keygen.Password).Methods("GET")

	// hashing
	r.HandleFunc("/hashing/md5", hashing.MD5).Methods("POST")
	r.HandleFunc("/hashing/sha-224", hashing.SHA224).Methods("POST")
	r.HandleFunc("/hashing/sha-256", hashing.SHA256).Methods("POST")
	r.HandleFunc("/hashing/sha-512", hashing.SHA512).Methods("POST")

	// auth
	r.HandleFunc("/auth/register", auth.Register).Methods("POST", "PUT")
	r.HandleFunc("/auth/login", auth.Login).Methods("POST")
	r.Handle("/auth/token-status", auth.JwtMiddleware.Handler(http.HandlerFunc(auth.TokenStatus))).Methods("GET")
	r.HandleFunc("/auth/username-status", auth.UsernameStatus).Methods("GET")
	r.Handle("/auth/change-username", auth.JwtMiddleware.Handler(http.HandlerFunc(auth.ChangeUsername))).Methods("POST")
	r.Handle("/auth/change-password", auth.JwtMiddleware.Handler(http.HandlerFunc(auth.ChangePassword))).Methods("POST")

	// persistance
	r.Handle("/keys", auth.JwtMiddleware.Handler(http.HandlerFunc(keys.ListKeys))).Methods("GET")
	r.Handle("/keys", auth.JwtMiddleware.Handler(http.HandlerFunc(keys.PersistKey))).Methods("POST", "PUT")
	r.Handle("/keys/{id:[0-9]+}", auth.JwtMiddleware.Handler(http.HandlerFunc(keys.RenameKey))).Methods("POST")
	r.Handle("/keys/{id:[0-9]+}", auth.JwtMiddleware.Handler(http.HandlerFunc(keys.DeleteKey))).Methods("DELETE")

	c := cors.AllowAll()
	
	// server configuration
	server := &http.Server{
		Handler:      c.Handler(r),
		Addr:         "127.0.0.1:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	// listen and serve
	log.Fatal(server.ListenAndServe())
}
