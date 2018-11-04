package hashing

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMD5Sample(t *testing.T) {
	payload := url.Values{"data": {"sample string to hash"}}
	req, err := http.NewRequest("POST", "/md5", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(MD5)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("MD5 returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	expected := "8bf8f77039f85bb72c3672e3173e8f40"
	if rr.Body.String() != expected {
		t.Errorf("MD5 returned unexpected body: got: %v, expected: %v", rr.Body.String(), expected)
	}
}

func TestMD5Empty(t *testing.T) {
	payload := url.Values{"data": {""}}
	req, err := http.NewRequest("POST", "/md5", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(MD5)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("MD5 returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	expected := "d41d8cd98f00b204e9800998ecf8427e"
	if rr.Body.String() != expected {
		t.Errorf("MD5 returned unexpected body: got: %v, expected: %v", rr.Body.String(), expected)
	}
}

func TestMD5Missing(t *testing.T) {
	req, err := http.NewRequest("POST", "/md5", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(MD5)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("MD5 returned incorrect status code: got: %v, expected: %v", status, http.StatusBadRequest)
	}
}

func TestSHA224Sample(t *testing.T) {
	payload := url.Values{"data": {"sample string to hash"}}
	req, err := http.NewRequest("POST", "/sha224", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(SHA224)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("SHA224 returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	expected := "b26bf601d18ac49bcb2a6434b7e183a28abb6a07b36ae44c0a985376"
	if rr.Body.String() != expected {
		t.Errorf("SHA224 returned unexpected body: got: %v, expected: %v", rr.Body.String(), expected)
	}
}

func TestSHA224Empty(t *testing.T) {
	payload := url.Values{"data": {""}}
	req, err := http.NewRequest("POST", "/sha224", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(SHA224)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("SHA224 returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	expected := "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
	if rr.Body.String() != expected {
		t.Errorf("SHA224 returned unexpected body: got: %v, expected: %v", rr.Body.String(), expected)
	}
}

func TestSHA224Missing(t *testing.T) {
	req, err := http.NewRequest("POST", "/sha224", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(SHA224)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("SHA224 returned incorrect status code: got: %v, expected: %v", status, http.StatusBadRequest)
	}
}

func TestSHA256Sample(t *testing.T) {
	payload := url.Values{"data": {"sample string to hash"}}
	req, err := http.NewRequest("POST", "/sha256", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(SHA256)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("SHA256 returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	expected := "76ecd71340ca903fe3693ce1b76fb119b526099ad887d42a89cba0644004a708"
	if rr.Body.String() != expected {
		t.Errorf("SHA256 returned unexpected body: got: %v, expected: %v", rr.Body.String(), expected)
	}
}

func TestSHA256Empty(t *testing.T) {
	payload := url.Values{"data": {""}}
	req, err := http.NewRequest("POST", "/sha256", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(SHA256)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("SHA256 returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if rr.Body.String() != expected {
		t.Errorf("SHA256 returned unexpected body: got: %v, expected: %v", rr.Body.String(), expected)
	}
}

func TestSHA256Missing(t *testing.T) {
	req, err := http.NewRequest("POST", "/sha256", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(SHA256)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("SHA256 returned incorrect status code: got: %v, expected: %v", status, http.StatusBadRequest)
	}
}

func TestSHA512Sample(t *testing.T) {
	payload := url.Values{"data": {"sample string to hash"}}
	req, err := http.NewRequest("POST", "/sha512", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(SHA512)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("SHA512 returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	expected := "4a5f8e06455b2bae4d2a1e381cc1fe5df8a3490672b19fcddfbf2797c2e372b5a1802f064e0e68119e24a32f05d453c5342552c418c7ea44bce27b5aa3f1b9f8"
	if rr.Body.String() != expected {
		t.Errorf("SHA512 returned unexpected body: got: %v, expected: %v", rr.Body.String(), expected)
	}
}

func TestSHA512Empty(t *testing.T) {
	payload := url.Values{"data": {""}}
	req, err := http.NewRequest("POST", "/sha512", strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(SHA512)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("SHA512 returned incorrect status code: got: %v, expected: %v", status, http.StatusOK)
	}

	expected := "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	if rr.Body.String() != expected {
		t.Errorf("SHA512 returned unexpected body: got: %v, expected: %v", rr.Body.String(), expected)
	}
}

func TestSHA512Missing(t *testing.T) {
	req, err := http.NewRequest("POST", "/sha512", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(SHA512)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("SHA256 returned incorrect status code: got: %v, expected: %v", status, http.StatusBadRequest)
	}
}
