package hashing

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"log"
	"net/http"
)

// MD5 - POST /md5
// Params:
// - data : data to hash
// Returns:
// - hash (plain text)
func MD5(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	values, ok := r.PostForm["data"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("no data to hash submitted"))
		return
	}

	result, err := GenerateHash(md5.New(), values[0])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("MD5: failed to write data to hash")
		return
	}
	w.Write([]byte(result))
}

// SHA224 - POST /sha224
// Params:
// - data : data to hash
// Returns:
// - hash (plain text)
func SHA224(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	values, ok := r.PostForm["data"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("no data to hash submitted"))
		return
	}

	result, err := GenerateHash(sha256.New224(), values[0])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("SHA224: failed to write data to hash")
		return
	}
	w.Write([]byte(result))
}

// SHA256 - POST /sha256
// Params:
// - data : data to hash
// Returns:
// - hash (plain text)
func SHA256(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	values, ok := r.PostForm["data"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("no data to hash submitted"))
		return
	}

	result, err := GenerateHash(sha256.New(), values[0])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("SHA256: failed to write data to hash")
		return
	}
	w.Write([]byte(result))
}

// SHA512 - POST /sha512
// Params:
// - data : data to hash
// Returns:
// - hash (plain text)
func SHA512(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	values, ok := r.PostForm["data"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("no data to hash submitted"))
		return
	}

	result, err := GenerateHash(sha512.New(), values[0])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("SHA512: failed to write data to hash")
		return
	}
	w.Write([]byte(result))
}

// GenerateHash is an utility function to generate a hex-encoded hash from given text using the hasher
func GenerateHash(hasher hash.Hash, data string) (string, error) {
	_, err := hasher.Write([]byte(data))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
