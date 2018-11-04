package dbhelper

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"../hashing"
	"../keygen"
)

// User data model
type User struct {
	ID           int
	Username     string
	PasswordHash string
	Salt         string
}

// Key data model
type Key struct {
	ID        int
	Name      string
	Type      string
	Value     string
	UserID    int
	CreatedOn time.Time
}

var db *sql.DB

// InitializeDatabase connects to the SQL database and verifies the connection
func InitializeDatabase(connStr string) (err error) {
	db, err = sql.Open("mysql", connStr)
	if err != nil {
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(10*time.Second))
	defer cancel()
	err = db.PingContext(ctx)
	return
}

// CreateUser creates a new user account in database
func CreateUser(username, password string) (err error) {
	statement, err := db.Prepare("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)")
	if err != nil {
		return
	}

	salt := generatePasswordSalt()
	passwordHash, err := ComputePasswordHash(password, salt)
	if err != nil {
		return
	}
	resource, err := statement.Exec(username, passwordHash, salt)
	if err != nil {
		return
	}

	rowCount, err := resource.RowsAffected()
	if err != nil {
		return
	} else if rowCount == 0 {
		err = errors.New("rows affected: 0, expected: 1")
		return
	}

	return
}

// FindUser retrieves user data for the user with provided id
func FindUser(id int) (user *User, err error) {
	statement, err := db.Prepare("SELECT id, username, salt FROM users WHERE id = ?")
	if err != nil {
		return
	}
	rows, err := statement.Query(id)
	if err != nil {
		return
	}
	defer rows.Close()

	if rows.Next() {
		user = new(User)
		if err = rows.Scan(&user.ID, &user.Username, &user.Salt); err != nil {
			return
		}
	}

	return
}

// FindUserByUsername retrieves user data for the user with provided username
func FindUserByUsername(username string) (user *User, err error) {
	statement, err := db.Prepare("SELECT id, username, password_hash, salt FROM users WHERE username = ?")
	if err != nil {
		return
	}
	rows, err := statement.Query(username)
	if err != nil {
		return
	}
	defer rows.Close()

	if rows.Next() {
		user = new(User)
		if err = rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Salt); err != nil {
			return
		}
	}

	return
}

// CheckUsernameStatus checks username availability
func CheckUsernameStatus(username string) (status bool, err error) {
	status = false
	statement, err := db.Prepare("SELECT COUNT(*) FROM users WHERE username = ?")
	if err != nil {
		return
	}
	rows, err := statement.Query(username)
	if err != nil {
		return
	}

	rowCount := 0
	for rows.Next() {
		if err = rows.Scan(&rowCount); err != nil {
			return
		}
	}
	rows.Close()

	status = rowCount == 0
	return
}

// ChangeUsername changes the given user's username
func ChangeUsername(userID int, username string) (err error) {
	statement, err := db.Prepare("UPDATE users SET username = ? WHERE id = ?")
	if err != nil {
		return
	}

	resource, err := statement.Exec(username, userID)
	if err != nil {
		return
	}

	rowCount, err := resource.RowsAffected()
	if err != nil {
		return
	} else if rowCount == 0 {
		err = errors.New("rows affected: 0, expected: 1")
		return
	}

	return
}

// ChangePassword changes the given user's password
func ChangePassword(userID int, password string) (err error) {
	statement, err := db.Prepare("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?")
	if err != nil {
		return
	}

	salt := generatePasswordSalt()
	passwordHash, err := ComputePasswordHash(password, salt)
	if err != nil {
		return
	}
	resource, err := statement.Exec(passwordHash, salt, userID)
	if err != nil {
		return
	}

	rowCount, err := resource.RowsAffected()
	if err != nil {
		return
	} else if rowCount == 0 {
		err = errors.New("rows affected: 0, expected: 1")
		return
	}

	return
}

// CreateKey persists a new key for this user
func CreateKey(name, keyType, value string, userID int) (err error) {
	statement, err := db.Prepare("INSERT INTO user_keys (key_name, key_type, key_value, user_id, created_on) VALUES (?, (SELECT id FROM key_types WHERE key_type_name = ?), ?, ?, CURRENT_TIMESTAMP)")
	if err != nil {
		return
	}
	resource, err := statement.Exec(name, keyType, value, userID)
	if err != nil {
		return
	}

	rowCount, err := resource.RowsAffected()
	if err != nil {
		return
	} else if rowCount == 0 {
		err = errors.New("rows affected: 0, expected: 1")
		return
	}

	return
}

// FindKey returns key with provided id
func FindKey(id int) (key *Key, err error) {
	statement, err := db.Prepare("SELECT user_keys.key_name, key_types.key_type_name, user_keys.key_value, user_keys.user_id, user_keys.created_on FROM user_keys INNER JOIN key_types ON user_keys.key_type = key_types.id WHERE user_keys.id = ?")
	if err != nil {
		return
	}
	rows, err := statement.Query(id)
	if err != nil {
		return
	}
	defer rows.Close()

	if rows.Next() {
		key = new(Key)
		if err = rows.Scan(&key.Name, &key.Type, &key.Value, &key.UserID, &key.CreatedOn); err != nil {
			return
		}
	}

	return
}

// FindAllKeys returns all keys for user with provided id
func FindAllKeys(userID, offset, count int) (keys []Key, total int, err error) {
	statement, err := db.Prepare("SELECT COUNT(*) FROM user_keys WHERE user_keys.user_id = ?")
	if err != nil {
		return
	}
	rowsCount, err := statement.Query(userID)
	if err != nil {
		return
	}
	defer rowsCount.Close()
	
	if rowsCount.Next() {
		if err = rowsCount.Scan(&total); err != nil {
			return
		}
	} else {
		err = errors.New("can not count user keys")
		return
	}
	
	statement, err = db.Prepare("SELECT user_keys.id, user_keys.key_name, key_types.key_type_name, user_keys.key_value, user_keys.user_id, user_keys.created_on FROM user_keys INNER JOIN key_types ON user_keys.key_type = key_types.id WHERE user_keys.user_id = ? LIMIT ?, ?")
	if err != nil {
		return
	}
	rows, err := statement.Query(userID, offset, count)
	if err != nil {
		return
	}
	defer rows.Close()

	keys = make([]Key, 0, 10) // sensible capacity choice
	for rows.Next() {
		key := Key{}
		if err = rows.Scan(&key.ID, &key.Name, &key.Type, &key.Value, &key.UserID, &key.CreatedOn); err != nil {
			return
		}
		keys = append(keys, key)
	}

	return
}

// RenameKey changes the given key's name
func RenameKey(id int, name string) (err error) {
	statement, err := db.Prepare("UPDATE user_keys SET key_name = ? WHERE id = ?")
	if err != nil {
		return
	}
	resource, err := statement.Exec(name, id)
	if err != nil {
		return
	}

	rowCount, err := resource.RowsAffected()
	if err != nil {
		return
	} else if rowCount == 0 {
		err = errors.New("rows affected: 0, expected: 1")
		return
	}

	return
}

// DeleteKey deletes a key from the database
func DeleteKey(id int) (err error) {
	statement, err := db.Prepare("DELETE FROM user_keys WHERE id = ?")
	if err != nil {
		return
	}
	resource, err := statement.Exec(id)
	if err != nil {
		return
	}

	rowCount, err := resource.RowsAffected()
	if err != nil {
		return
	} else if rowCount == 0 {
		err = errors.New("rows affected: 0, expected: 1")
		return
	}

	return
}

// ComputePasswordHash generates a password hash given password and salt
func ComputePasswordHash(password, salt string) (result string, err error) {
	result, err = hashing.GenerateHash(sha256.New(), password+salt)
	return
}

func generatePasswordSalt() string {
	return keygen.GeneratePassword(9, 9, 3, 11)
}
