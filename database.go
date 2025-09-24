package main

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

// Function starts database connection. In golang sql.Open does not check if database is accessible
// so db.Ping() is used to check this
func initDB(settings Settings) (*sql.DB, error) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@/%s", settings.DBUsername, settings.DBPassword, settings.DBName))
	if err != nil {
		return nil, err
	}
	err = db.Ping()
	if err != nil {
		return nil, err
	}
	return db, nil
}

// Function adds user to database.
// Returns ErrUserExists if user exists
// Adds user with given username, password and admin status to "users" table
// Bcrypt is used for password hashing
func addUser(db *sql.DB, user UserCredentials) error {
	exists, err := isUserExists(db, user.Username)
	if err != nil {
		return err
	}
	if exists {
		return ErrUserExists{"Error addUser: User already exists"}
	}
	userPasswdHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
	if err != nil {
		return err
	}
	_, err = db.Exec("INSERT INTO users (username, passwd_hash, date_created, is_admin, is_banned) VALUES(?, ?, NOW(), ?, 0)", user.Username, string(userPasswdHash), user.IsAdmin)
	if err != nil {
		return err
	}
	return nil
}

// Function checks if user exists
func isUserExists(db *sql.DB, username string) (bool, error) {
	var result string
	row := db.QueryRow("SELECT 1 FROM users WHERE username=?", username)
	err := row.Scan(&result)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		} else {
			return false, err
		}
	}
	return true, nil
}

// Function checks if password is correct. Bcrypt is used for password hashing.
// Returns ErrUserNotExists if user does not exist
// Checks "passwd_hash" column "users" table
// bcrypt is used for password hashing
func isCorrectPassword(db *sql.DB, user UserCredentials) (bool, error) {
	ok, err := isUserExists(db, user.Username)
	if err != nil {
		return false, err
	} else if !ok {
		return false, ErrUserNotExists{message: "Error isCorrectPassword: User does not exist"}
	}
	var userPasswdHash string
	row := db.QueryRow("SELECT passwd_hash FROM users WHERE username=?", user.Username)
	err = row.Scan(&userPasswdHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, ErrUserNotExists{message: "Error isCorrectPassword: User does not exist"}
		}
		return false, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(userPasswdHash), []byte(user.Password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Function checks if user is banned
// Returns ErrUserNotExists if user does not exist
// Function returns boolean value
func isBannedUser(db *sql.DB, username string) (bool, error) {
	ok, err := isUserExists(db, username)
	if err != nil {
		return false, err
	} else if !ok {
		return false, ErrUserNotExists{message: "Error isCorrectPassword: User does not exist"}
	}
	var isBanned int
	row := db.QueryRow("SELECT is_banned FROM users WHERE username=?", username)
	err = row.Scan(&isBanned)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, ErrUserNotExists{message: "Error isBannedUser: User does not exist"}
		}
		return false, err
	}
	if isBanned == 0 {
		return false, nil
	}
	return true, nil
}

func changeUsername(db *sql.DB, user UserCredentials, newUsername string) error {
	return nil
}

func changeUserPasswd(db *sql.DB, user UserCredentials, newPasswd string) error {
	return nil
}

func banUser(db *sql.DB, user UserCredentials) error {
	return nil
}

func unbanUser(db *sql.DB, user UserCredentials) error {
	return nil
}

func enableUserAdmin(db *sql.DB, user UserCredentials) error {
	return nil
}

func disableUserAdmin(db *sql.DB, user UserCredentials) error {
	return nil
}
