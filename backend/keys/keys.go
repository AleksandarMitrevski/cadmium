package keys

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"../dbhelper"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

const DEFAULT_ITEMS_PER_PAGE = 10

// ListKeys - GET /keys, authenticated
// Params:
// - page: one-based page index (optional, defaults to 1)
// - itemsPerPage: positive integer (optional, defaults to 10)
// Returns:
// - list of keys for the authenticated user and total key count in JSON format:
//   "keys": [
//	   {
//	     "id": non-negative integer,
//	     "name": string,
//	     "type": string: RSA, AES, Blowfish, Twofish or Password,
//	     "value": string
//     },
//     ...
//   ],
//   "total": non-negative integer
func ListKeys(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	r.ParseForm()
	page := 1
	itemsPerPage := DEFAULT_ITEMS_PER_PAGE

	pageValues, ok := r.Form["page"]
	if ok {
		pageParam, err := strconv.Atoi(pageValues[0])
		if err == nil && pageParam >= 1 {
			page = pageParam
		}
	}
	itemsPerPageValues, ok := r.Form["itemsPerPage"]
	if ok {
		itemsPerPageParam, err := strconv.Atoi(itemsPerPageValues[0])
		if err == nil && itemsPerPageParam > 0 {
			itemsPerPage = itemsPerPageParam
		}
	}

	keys, keysTotal, err := dbhelper.FindAllKeys(userID, (page-1)*itemsPerPage, itemsPerPage)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("can not retrieve keys for user: %v", err)
		return
	}
	
	result := struct {
		Keys  []dbhelper.Key `json:"keys"`
		Total int            `json:"total"`
	}{
		Keys: keys,
		Total: keysTotal,
	}
	json, err := json.Marshal(result)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("can not serialize keys to json: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

// PersistKey - POST /keys, PUT /keys, authenticated
// Params:
// - name: string
// - type: string: RSA, AES, Blowfish, Twofish or Password,
// - value: string
// Returns:
// Status code 200 on success
func PersistKey(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	r.ParseForm()

	missing := make([]string, 0, 3)
	nameValues, ok := r.PostForm["name"]
	if !ok {
		missing = append(missing, "name")
	}
	typeValues, ok := r.PostForm["type"]
	if !ok {
		missing = append(missing, "type")
	}
	valueValues, ok := r.PostForm["value"]
	if !ok {
		missing = append(missing, "value")
	}
	if len(missing) > 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing fields: " + strings.Join(missing, ", ")))
		return
	}

	incorrect := make([]string, 0, 2)
	name := nameValues[0]
	keyType := typeValues[0]
	if keyType != "RSA" && keyType != "AES" && keyType != "Blowfish" && keyType != "Twofish" && keyType != "Password" {
		incorrect = append(incorrect, "type")
	}
	value := valueValues[0]
	if len(value) == 0 {
		incorrect = append(incorrect, "value")
	}
	if len(incorrect) > 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("incorrect fields: " + strings.Join(incorrect, ", ")))
		return
	}

	if err := dbhelper.CreateKey(name, keyType, value, userID); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("can not create key: %v", err)
	}
}

// RenameKey - POST /keys/{id:[0-9]+}, authenticated
// Params:
// - name: string
// Returns:
// Status code 200 on success
func RenameKey(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	vars := mux.Vars(r)
	keyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid key"))
		return
	}

	key, err := dbhelper.FindKey(keyID)
	if err != nil || userID != key.UserID {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid key"))
		return
	}

	r.ParseForm()
	nameValues, ok := r.PostForm["name"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing field name"))
		return
	}

	if err := dbhelper.RenameKey(keyID, nameValues[0]); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("can not rename key: %v", err)
	}
}

// DeleteKey - DELETE /keys/{id:[0-9]+}, authenticated
// Path params:
// - id: the id of the key to delete belonging to the authenticated user
// Returns:
// Status code 200 on success
func DeleteKey(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	vars := mux.Vars(r)
	keyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid key"))
		return
	}

	key, err := dbhelper.FindKey(keyID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid key"))
		return
	}

	if userID != key.UserID {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid key"))
		return
	}

	if err := dbhelper.DeleteKey(keyID); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("can not delete key: %v", err)
	}
}

func getUserID(r *http.Request) int {
	token := r.Context().Value("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)
	return int(claims["user_id"].(float64))
}
