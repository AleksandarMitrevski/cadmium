package encrypt

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"../keygen"
)

func TestRSA(t *testing.T) {
	req, err := http.NewRequest("GET", "/rsa/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "2048")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(keygen.RSAKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Key generation returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}
	keys := rr.Body.String()
	keySplit := strings.Split(keys, "-----\n-----")
	if len(keySplit) != 2 {
		t.Error("Generated key can not be split into private and public key parts")
	}
	privateKey := keySplit[0] + "-----"
	publicKey := "-----" + keySplit[1]

	data := "sample text to encrypt"
	payload := url.Values{"key": {publicKey}, "data": {data}}
	req, err = http.NewRequest("POST", "/rsa/encrypt", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(RSAEncrypt)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("RSAEncrypt incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	encryptedData := rr.Body.String()
	if data == encryptedData {
		t.Error("RSAEncrypt does nothing")
	}

	payload = url.Values{"key": {privateKey}, "data": {encryptedData}}
	req, err = http.NewRequest("POST", "/rsa/decrypt", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(RSADecrypt)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("RSADecrypt incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	decryptedData := rr.Body.String()
	if data != decryptedData {
		t.Error("RSAEncrypt and RSADecrypt are not inverse operations")
	}
}

func TestAES(t *testing.T) {
	req, err := http.NewRequest("GET", "/aes/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "256")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(keygen.AESKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Key generation returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}
	key := rr.Body.String()

	data := "sample text to encrypt"
	payload := url.Values{"key": {key}, "data": {data}}
	req, err = http.NewRequest("POST", "/aes/encrypt", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(AESEncrypt)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("AESEncrypt incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	encryptedData := rr.Body.String()
	if data  == encryptedData {
		t.Error("AESEncrypt does nothing")
	}

	payload = url.Values{"key": {key}, "data": {encryptedData}}
	req, err = http.NewRequest("POST", "/aes/decrypt", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(AESDecrypt)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("AESDecrypt incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	decryptedData := rr.Body.String()
	if data  != decryptedData {
		t.Error("AESEncrypt and AESDecrypt are not inverse operations")
	}
}

func TestBlowfish(t *testing.T) {
	req, err := http.NewRequest("GET", "/blowfish/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "256")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(keygen.BlowfishKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Key generation returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}
	key := rr.Body.String()

	data  := "sample text to encrypt"
	payload := url.Values{"key": {key}, "data": {data }}
	req, err = http.NewRequest("POST", "/blowfish/encrypt", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(BlowfishEncrypt)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("BlowfishEncrypt incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	encryptedData := rr.Body.String()
	if data  == encryptedData {
		t.Error("BlowfishEncrypt does nothing")
	}

	payload = url.Values{"key": {key}, "data": {encryptedData}}
	req, err = http.NewRequest("POST", "/blowfish/decrypt", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(BlowfishDecrypt)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("BlowfishDecrypt incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	decryptedData := rr.Body.String()
	if data  != decryptedData {
		t.Error("BlowfishEncrypt and BlowfishDecrypt are not inverse operations")
	}
}

func TestTwofish(t *testing.T) {
	req, err := http.NewRequest("GET", "/twofish/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("keyLength", "256")
	req.URL.RawQuery = query.Encode()

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(keygen.TwofishKey)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Key generation returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}
	key := rr.Body.String()

	data  := "sample text to encrypt"
	payload := url.Values{"key": {key}, "data": {data }}
	req, err = http.NewRequest("POST", "/twofish/encrypt", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(TwofishEncrypt)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("TwofishEncrypt incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	encryptedData := rr.Body.String()
	if data  == encryptedData {
		t.Error("TwofishEncrypt does nothing")
	}

	payload = url.Values{"key": {key}, "data": {encryptedData}}
	req, err = http.NewRequest("POST", "/twofish/decrypt", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(TwofishDecrypt)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("TwofishEncrypt incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	decryptedData := rr.Body.String()
	if data  != decryptedData {
		t.Error("TwofishEncrypt and TwofishDecrypt are not inverse operations")
	}
}
