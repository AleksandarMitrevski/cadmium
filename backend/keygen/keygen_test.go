package keygen

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestRSAValid2048(t *testing.T) {
	req, err := http.NewRequest("GET", "/rsa/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "2048")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(RSAKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("RSAKey returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	keys := rr.Body.String()
	validateRSAKeys := func(keys string) bool {
		pk, rest := pem.Decode([]byte(keys))
		_, err = x509.ParsePKCS1PrivateKey(pk.Bytes)
		if err != nil {
			return false
		}
		pubk, _ := pem.Decode([]byte(rest))
		_, err = x509.ParsePKCS1PublicKey(pubk.Bytes)
		if err != nil {
			return false
		}
		return true
	}

	if !validateRSAKeys(keys) {
		t.Error("Generated keys are invalid.")
	}
}

func TestRSAInvalidKeyLength(t *testing.T) {
	req, err := http.NewRequest("GET", "/rsa/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "2049")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(RSAKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("RSAKey returned incorrect status code: got: %v, expected: %v", status, http.StatusBadRequest)
	}
}

func TestAESValid128(t *testing.T) {
	req, err := http.NewRequest("GET", "/aes/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "128")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(AESKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("AESKey returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	generatedKey := rr.Body.String()
	bytes, err := hex.DecodeString(generatedKey)
	if err != nil {
		t.Errorf("Generated key %v is invalid: %v", generatedKey, err.Error())
	}
	if len(bytes) != 16 {
		t.Errorf("Generated key %v is not 128-bit, but %v-bit instead.", generatedKey, strconv.Itoa(len(bytes)*8))
	}
}

func TestAESValid192(t *testing.T) {
	req, err := http.NewRequest("GET", "/aes/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "192")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(AESKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("AESKey returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	generatedKey := rr.Body.String()
	bytes, err := hex.DecodeString(generatedKey)
	if err != nil {
		t.Errorf("Generated key %v is invalid: %v", generatedKey, err.Error())
	}
	if len(bytes) != 24 {
		t.Errorf("Generated key %v is not 192-bit, but %v-bit instead.", generatedKey, strconv.Itoa(len(bytes)*8))
	}
}

func TestAESValid256(t *testing.T) {
	req, err := http.NewRequest("GET", "/aes/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "256")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(AESKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("AESKey returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	generatedKey := rr.Body.String()
	bytes, err := hex.DecodeString(generatedKey)
	if err != nil {
		t.Errorf("Generated key %v is invalid: %v", generatedKey, err.Error())
	}
	if len(bytes) != 32 {
		t.Errorf("Generated key %v is not 256-bit, but %v-bit instead.", generatedKey, strconv.Itoa(len(bytes)*8))
	}
}

func TestAESMissingKeyLength(t *testing.T) {
	req, err := http.NewRequest("GET", "/aes/key", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(AESKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("AESKey returned incorrect status code: got: %v, expected: %v", status, http.StatusBadRequest)
	}

	body := rr.Body.String()
	expectedBody := "missing field keyLength"
	if body != expectedBody {
		t.Errorf("AESKey returned incorrect error message: expected: %v, got: %v", body, expectedBody)
	}
}

func TestAESInvalidKeyLength(t *testing.T) {
	req, err := http.NewRequest("GET", "/aes/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "sdf")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(AESKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("AESKey returned incorrect status code: got: %v, expected: %v", status, http.StatusBadRequest)
	}

	body := rr.Body.String()
	expectedBody := "invalid keyLength - supported values: 128, 192, 256"
	if body != expectedBody {
		t.Errorf("AESKey returned incorrect error message: expected: %v, got: %v", body, expectedBody)
	}
}

func TestAESIncorrectKeyLength(t *testing.T) {
	req, err := http.NewRequest("GET", "/aes/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "123")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(AESKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("AESKey returned incorrect status code: got: %v, expected: %v", status, http.StatusBadRequest)
	}

	body := rr.Body.String()
	expectedBody := "invalid keyLength - supported values: 128, 192, 256"
	if body != expectedBody {
		t.Errorf("AESKey returned incorrect error message: expected: %v, got: %v", body, expectedBody)
	}
}

func TestBlowfishValid256(t *testing.T) {
	req, err := http.NewRequest("GET", "/blowfish/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "256")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(BlowfishKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("BlowfishKey returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	generatedKey := rr.Body.String()
	bytes, err := hex.DecodeString(generatedKey)
	if err != nil {
		t.Errorf("Generated key %v is invalid: %v", generatedKey, err.Error())
	}
	if len(bytes) != 32 {
		t.Errorf("Generated key %v is not 256-bit, but %v-bit instead.", generatedKey, strconv.Itoa(len(bytes)*8))
	}
}

func TestBlowfishIncorrectKeyLength(t *testing.T) {
	req, err := http.NewRequest("GET", "/blowfish/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "262")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(BlowfishKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("BlowfishKey returned incorrect status code: got: %v, expected: %v", status, http.StatusBadRequest)
	}

	body := rr.Body.String()
	expectedBody := "invalid keyLength - supported values are larger or equal to 32, smaller or equal to 448 and divisible by 8"
	if body != expectedBody {
		t.Errorf("BlowfishKey returned incorrect error message: expected: %v, got: %v", body, expectedBody)
	}
}

func TestTwofishValid256(t *testing.T) {
	req, err := http.NewRequest("GET", "/twofish/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "256")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(TwofishKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("TwofishKey returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	generatedKey := rr.Body.String()
	bytes, err := hex.DecodeString(generatedKey)
	if err != nil {
		t.Errorf("Generated key %v is invalid: %v", generatedKey, err.Error())
	}
	if len(bytes) != 32 {
		t.Errorf("Generated key %v is not 256-bit, but %v-bit instead.", generatedKey, strconv.Itoa(len(bytes)*8))
	}
}

func TestTwofishIncorrectKeyLength(t *testing.T) {
	req, err := http.NewRequest("GET", "/twofish/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "184")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(TwofishKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("TwofishKey returned incorrect status code: got: %v, expected: %v", status, http.StatusBadRequest)
	}

	body := rr.Body.String()
	expectedBody := "invalid keyLength - supported values: 128, 192, 256"
	if body != expectedBody {
		t.Errorf("TwofishKey returned incorrect error message: expected: %v, got: %v", body, expectedBody)
	}
}

func TestPasswordValid(t *testing.T) {
	payload := url.Values{"alphaLower": {"5"}, "alphaUpper": {"5"}, "numeric": {"5"}, "special": {"5"}}
	req, err := http.NewRequest("POST", "/password", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(Password)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Password returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	generatedPassword := rr.Body.String()
	if len(generatedPassword) != 20 {
		t.Errorf("Generated password has incorrect length: got: %v, expected: %v", len(generatedPassword), 20)
	}

	alphaLower := "abcdefghijklmnopqrstuvwxyz"
	alphaUpper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numeric := "0123456789"
	special := " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	alphaLowerCount, alphaUpperCount, numericCount, specialCount := uint(0), uint(0), uint(0), uint(0)

	for _, char := range generatedPassword {
		if strings.ContainsRune(alphaLower, char) {
			alphaLowerCount++
		} else if strings.ContainsRune(alphaUpper, char) {
			alphaUpperCount++
		} else if strings.ContainsRune(numeric, char) {
			numericCount++
		} else if strings.ContainsRune(special, char) {
			specialCount++
		} else {
			t.Errorf("Generated password %v contains invalid characters.", generatedPassword)
		}
	}

	incorrectCounts := make([]string, 0, 4)
	if alphaLowerCount != 5 {
		incorrectCounts = append(incorrectCounts, "alphaLower")
	}
	if alphaUpperCount != 5 {
		incorrectCounts = append(incorrectCounts, "alphaUpper")
	}
	if numericCount != 5 {
		incorrectCounts = append(incorrectCounts, "numeric")
	}
	if specialCount != 5 {
		incorrectCounts = append(incorrectCounts, "special")
	}

	if len(incorrectCounts) > 0 {
		t.Errorf("Incorrect counts in generated password %v: %v", generatedPassword, strings.Join(incorrectCounts, ", "))
	}
}

func TestPasswordInvalidNegative(t *testing.T) {
	payload := url.Values{"alphaLower": {"-5"}, "alphaUpper": {"0"}, "numeric": {"-5"}, "special": {"5"}}
	req, err := http.NewRequest("POST", "/password", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(Password)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Password returned incorrect status code: got: %v, expected: %v", status, http.StatusBadRequest)
	}

	body := rr.Body.String()
	expectedBody := "incorrect fields: alphaLower, numeric"
	if body != expectedBody {
		t.Errorf("Generated password returned incorrect error message: got: %v, expected: %v", body, expectedBody)
	}
}

func TestPasswordInvalidZeroLength(t *testing.T) {
	payload := url.Values{"alphaLower": {"0"}, "alphaUpper": {"0"}, "numeric": {"0"}, "special": {"0"}}
	req, err := http.NewRequest("POST", "/password", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(Password)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Password returned incorrect status code: got: %v, expected: %v", status, http.StatusBadRequest)
	}

	body := rr.Body.String()
	expectedBody := "effective password length can not be 0"
	if body != expectedBody {
		t.Errorf("Generated password returned incorrect error message: got: %v, expected: %v", body, expectedBody)
	}
}
