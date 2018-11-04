package keygen

import (
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
)

// RSAKey - GET /rsa/key
// Params:
//	- keyLength: non-negative integer representing the key length in bits; supported values are 1024, 2048, 3072, 4096.
// Returns:
//	- private key in ASN.1 DER format, new line (\n), public key in ASN.1 DER format
// Implementation is based on: https://gist.github.com/devinodaniel/8f9b8a4f31573f428f29ec0e884e6673
func RSAKey(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	keyLengthValues, ok := r.Form["keyLength"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing field keyLength"))
		return
	}

	keyLength, err := strconv.Atoi(keyLengthValues[0])
	if err != nil || (keyLength != 1024 && keyLength != 2048 && keyLength != 3072 && keyLength != 4096) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid keyLength - supported values: 1024, 2048, 3072, 4096"))
		return
	}

	privateKey, publicKey, err := generateRSAKeys(uint(keyLength / 8))
	if err != nil {
		log.Printf("generateRSAKeys() failed with error %v", err.Error())
	}

	w.Write(privateKey)
	w.Write(publicKey)
}

// AESKey - GET /aes/key
// Params:
// - keyLength : non-negative integer representing the key length in bits; supported values are 128, 192, 256.
// Returns:
// - random hex-encoded key (plain text)
func AESKey(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	keyLengthValues, ok := r.Form["keyLength"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing field keyLength"))
		return
	}

	keyLength, err := strconv.Atoi(keyLengthValues[0])
	if err != nil || (keyLength != 128 && keyLength != 192 && keyLength != 256) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid keyLength - supported values: 128, 192, 256"))
		return
	}

	result, err := generateKey(uint(keyLength / 8))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("generateKey() can not generate key: %v", err.Error())
		return
	}
	w.Write([]byte(result))
}

// BlowfishKey - GET /blowfish/key
// Params:
// - keyLength : non-negative integer representing the key length in bits; supported values are {32 + 8k | 0 <= k <= 52}.
// Returns:
// - random hex-encoded key (plain text)
func BlowfishKey(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	keyLengthValues, ok := r.Form["keyLength"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing field keyLength"))
		return
	}

	keyLength, err := strconv.Atoi(keyLengthValues[0])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid field keyLength"))
		return
	}
	if keyLength < 32 || keyLength >= 448 || keyLength%8 != 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid keyLength - supported values are larger or equal to 32, smaller or equal to 448 and divisible by 8"))
		return
	}

	result, err := generateKey(uint(keyLength / 8))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("generateKey() can not generate key: %v", err.Error())
		return
	}
	w.Write([]byte(result))
}

// TwofishKey - GET /twofish/key
// Params:
// - keyLength : non-negative integer representing the key length in bits; supported values are 128, 192, 256.
// Returns:
// - random hex-encoded key (plain text)
func TwofishKey(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	keyLengthValues, ok := r.Form["keyLength"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing field keyLength"))
		return
	}

	keyLength, err := strconv.Atoi(keyLengthValues[0])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid field keyLength"))
		return
	}
	if keyLength != 128 && keyLength != 192 && keyLength != 256 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid keyLength - supported values: 128, 192, 256"))
		return
	}

	result, err := generateKey(uint(keyLength / 8))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("generateKey() can not generate key: %v", err.Error())
		return
	}
	w.Write([]byte(result))
}

// Password - GET /password
// Params:
// - alphaLower : non-negative integer
// - alphaUpper : non-negative integer
// - numeric : non-negative integer
// - special : non-negative integer
// Returns:
// - random password (plain text)
func Password(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	missingFields := make([]string, 0, 4)
	alphaLowerValues, ok := r.Form["alphaLower"]
	if !ok {
		missingFields = append(missingFields, "alphaLower")
	}
	alphaUpperValues, ok := r.Form["alphaUpper"]
	if !ok {
		missingFields = append(missingFields, "alphaUpper")
	}
	numericValues, ok := r.Form["numeric"]
	if !ok {
		missingFields = append(missingFields, "numeric")
	}
	specialValues, ok := r.Form["special"]
	if !ok {
		missingFields = append(missingFields, "special")
	}
	if len(missingFields) > 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing fields: " + strings.Join(missingFields, ", ")))
		return
	}

	incorrectFields := make([]string, 0, 4)
	alphaLower, err := strconv.Atoi(alphaLowerValues[0])
	if err != nil || alphaLower < 0 {
		incorrectFields = append(incorrectFields, "alphaLower")
	}
	alphaUpper, err := strconv.Atoi(alphaUpperValues[0])
	if err != nil || alphaUpper < 0 {
		incorrectFields = append(incorrectFields, "alphaUpper")
	}
	numeric, err := strconv.Atoi(numericValues[0])
	if err != nil || numeric < 0 {
		incorrectFields = append(incorrectFields, "numeric")
	}
	special, err := strconv.Atoi(specialValues[0])
	if err != nil || special < 0 {
		incorrectFields = append(incorrectFields, "special")
	}
	if len(incorrectFields) > 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("incorrect fields: " + strings.Join(incorrectFields, ", ")))
		return
	}
	if alphaLower == 0 && alphaUpper == 0 && numeric == 0 && special == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("effective password length can not be 0"))
		return
	}

	result := GeneratePassword(uint(alphaLower), uint(alphaUpper), uint(numeric), uint(special))
	w.Write([]byte(result))
}

func generateRSAKeys(bytesCount uint) ([]byte, []byte, error) {
	// generate private key
	pk, err := rsa.GenerateKey(crand.Reader, int(bytesCount*8))
	if err != nil {
		return nil, nil, err
	}
	err = pk.Validate()
	if err != nil {
		return nil, nil, err
	}

	// output private key in ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(pk)
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}
	privatePEM := pem.EncodeToMemory(&privBlock)

	// output public key in ASN.1 DER format
	pubDER := x509.MarshalPKCS1PublicKey(&pk.PublicKey)
	pubBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   pubDER,
	}
	publicPEM := pem.EncodeToMemory(&pubBlock)

	return privatePEM, publicPEM, nil
}

func generateKey(bytesCount uint) (string, error) {
	key := make([]byte, bytesCount)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// GeneratePassword generates a random string given the character group counts
func GeneratePassword(alphaLowerCount, alphaUpperCount, numericCount, specialCount uint) string {
	alphaLower := "abcdefghijklmnopqrstuvwxyz"
	alphaUpper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numeric := "0123456789"
	special := " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

	result := make([]byte, 0, alphaLowerCount+alphaUpperCount+numericCount+specialCount)

	alphaLowerLength := len(alphaLower)
	for i := uint(0); i < alphaLowerCount; i++ {
		result = append(result, alphaLower[rand.Intn(alphaLowerLength)])
	}
	alphaUpperLength := len(alphaUpper)
	for i := uint(0); i < alphaUpperCount; i++ {
		result = append(result, alphaUpper[rand.Intn(alphaUpperLength)])
	}
	numericLength := len(numeric)
	for i := uint(0); i < numericCount; i++ {
		result = append(result, numeric[rand.Intn(numericLength)])
	}
	specialLength := len(special)
	for i := uint(0); i < specialCount; i++ {
		result = append(result, special[rand.Intn(specialLength)])
	}

	return permute(string(result))
}

func permute(text string) string {
	var buffer bytes.Buffer
	for len(text) > 0 {
		index := rand.Intn(len(text))
		buffer.WriteByte(text[index])
		text = text[:index] + text[index+1:]
	}
	return buffer.String()
}
