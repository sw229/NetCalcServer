package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/sw229/netCalcServer/internal/types"
	"golang.org/x/crypto/bcrypt"
)

type IDbConnection interface {
	// Function returns a list of ALL users
	ListAllUsers() ([]types.DisplayedUserData, error)

	// Function returns a list of users with specified usernames. A user absent from the database is ignored
	ListUsers([]string) ([]types.DisplayedUserData, error)

	// Function adds user to database. Returns ErrUserExists if user exists
	AddUser(types.UserCredentials) error

	// Function deletes specified user. Returns ErrUserNotExists if user does not exist
	DeleteUser(string) error

	// Function checks if password is correct. Returns ErrUserNotExists if user does not exist
	IsCorrectPassword(types.UserCredentials) (bool, error)

	// Fucntion checks if user is banned. Returns ErrUserNotExists if user does not exist
	IsBannedUser(username string) (bool, error)

	// Fucntion checks if user is admin. Returns ErrUserNotExists if user does not exist
	IsAdmin(username string) (bool, error)

	// Function changes username of a user whose name is passed as the first operand
	// to value passed as the second operand.
	// ErrUserNotExists returned if user with oldUserName does not exist
	// ErrUserExist returned if user with newUserName already exists
	ChangeUsername(string, string) error

	// Function changes password of a user whose username is passed as the first argument
	// to value passed as the second argument.
	// ErrUserNotExists returned if user does not exist
	// ErrInvalidPassword returned if password is invalid
	ChangeUserPasswd(string, string) error

	// Function bans a user
	// ErrUserNotExists returned if user does not exist
	// ErrUserStatusUnchanged returned if user already banned
	BanUser(string) error

	// Function unbans a user
	// ErrUserNotExists returned if user does not exist
	// ErrUserStatusUnchanged returned if user is not banned
	UnbanUser(string) error

	// Function enables admin rights for a user
	// ErrUserNotExists returned if user does not exist
	// ErrUserStatusUnchanged returned if user is already admin
	EnableUserAdmin(string) error

	// Function disables admin rights for a user
	// ErrUserNotExists returned if user does not exist
	// ErrUserStatusUnchanged returned if user is not an admin
	DisableUserAdmin(string) error
}

type MysqlConnection struct {
}

// Function starts database connection. In golang sql.Open does not check if database is accessible
// so db.Ping() is used to check this
func InitDB(settings types.Settings) (*sql.DB, error) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@/%s", *settings.DBUsername, *settings.DBPassword, *settings.DBName))
	if err != nil {
		return nil, err
	}
	err = db.Ping()
	if err != nil {
		return nil, err
	}
	return db, nil
}

// Function returns a list of ALL users
func ListAllUsers(db *sql.DB) ([]types.DisplayedUserData, error) {
	rows, err := db.Query("SELECT username, date_created, is_admin, is_banned FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []types.DisplayedUserData

	for rows.Next() {
		var user types.DisplayedUserData
		var dateCreatedStr string
		err := rows.Scan(&user.Username, &dateCreatedStr, &user.IsAdmin, &user.IsBanned)
		if err != nil {
			return nil, err
		}
		if user.DateCreated, err = time.Parse("2006-01-02 15:04:05", dateCreatedStr); err != nil {
			return nil, fmt.Errorf("failed to parse date_created: '%s': %w", dateCreatedStr, err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

// Function returns a list of users with specified usernames
// Users absent from the database are ignored
func ListUsers(db *sql.DB, usernames []string) ([]types.DisplayedUserData, error) {
	users := []types.DisplayedUserData{}
	placeholders := make([]string, len(usernames))
	queryArgs := make([]interface{}, len(usernames))
	for i, name := range usernames {
		placeholders[i] = "?"
		queryArgs[i] = name
	}
	placeholderStr := strings.Join(placeholders, ",")
	rows, err := db.Query(
		fmt.Sprintf(
			"SELECT username, date_created, is_admin, is_banned FROM users WHERE username IN (%s)",
			placeholderStr,
		),
		queryArgs...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var user types.DisplayedUserData
		var dateCreatedStr string
		err = rows.Scan(&user.Username, &dateCreatedStr, &user.IsAdmin, &user.IsBanned)
		if err != nil {
			return nil, err
		}
		if user.DateCreated, err = time.Parse("2006-01-02 15:04:05", dateCreatedStr); err != nil {
			return nil, fmt.Errorf("failed to parse date_created: '%s': %w", dateCreatedStr, err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

// Function adds user to database.
// Returns ErrUserExists if user exists
// Adds user with given username, password and admin status to "users" table
// Bcrypt is used for password hashing
func AddUser(db *sql.DB, user types.UserCredentials) error {
	exists, err := isUserExists(db, user.Username)
	if err != nil {
		return err
	}
	if exists {
		return types.ErrUserExists{Message: "Error addUser: User already exists"}
	}
	if !isValidUsername(user.Username) {
		return types.ErrInvalidNameOrPasswd{Message: "Error addUser: Invalid username"}
	}
	if !isValidPasswd(user.Password) {
		return types.ErrInvalidNameOrPasswd{Message: "Error addUser: Invalid password"}
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

// Function deletes specified user
// Returns ErrUserNotExists if user does not exist
func DeleteUser(db *sql.DB, username string) error {
	exists, err := isUserExists(db, username)
	if err != nil {
		return err
	}
	if !exists {
		return types.ErrUserNotExists{Message: "Error deleteUser: User does not exist"}
	}
	_, err = db.Exec("DELETE FROM users WHERE username = ?", username)
	if err != nil {
		return err
	}
	return nil
}

// Function checks if password is correct. Bcrypt is used for password hashing.
// Returns ErrUserNotExists if user does not exist
// Checks "passwd_hash" column "users" table
// bcrypt is used for password hashing
func IsCorrectPassword(db *sql.DB, user types.UserCredentials) (bool, error) {
	var userPasswdHash string
	row := db.QueryRow("SELECT passwd_hash FROM users WHERE username=?", user.Username)
	err := row.Scan(&userPasswdHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, types.ErrUserNotExists{Message: "Error IsCorrectPassword: User does not exist"}
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

// Function checks if user is banned, returns boolean
// Returns ErrUserNotExists if user does not exist
// If error is encountered, functuin returns false
func IsBannedUser(db *sql.DB, username string) (bool, error) {
	var isBanned int
	row := db.QueryRow("SELECT is_banned FROM users WHERE username=?", username)
	err := row.Scan(&isBanned)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, types.ErrUserNotExists{Message: "Error IsBannedUser: User does not exist"}
		}
		return false, err
	}
	if isBanned == 0 {
		return false, nil
	}
	return true, nil
}

// Function checks if user is admin, returns boolean
// ErrUserNotExists returned if user does not exist
// If error is encountered, functuin returns false
func IsAdmin(db *sql.DB, username string) (bool, error) {
	var isAdmin int
	row := db.QueryRow("SELECT is_admin FROM users WHERE username=?", username)
	err := row.Scan(&isAdmin)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, types.ErrUserNotExists{Message: "Error isAdmin: User does not exist"}
		}
		return false, err
	}
	if isAdmin == 0 {
		return false, nil
	}
	return true, nil
}

// Function changes username from oldUsername to newUsername
// ErrUserNotExists returned if user with oldUserName does not exist
// ErrUserExist returned if user with newUserName already exists
func ChangeUsername(db *sql.DB, oldUsername, newUsername string) error { // TODO: use transactions
	ok, err := isUserExists(db, oldUsername)
	if err != nil {
		return err
	} else if !ok {
		return types.ErrUserNotExists{Message: "Error changeUsername: User does not exist"}
	}

	exists, err := isUserExists(db, newUsername)
	if err != nil {
		return err
	}
	if exists {
		return types.ErrUserExists{Message: "Error changeUsername: Username taken"}
	}

	_, err = db.Exec("UPDATE users SET username=? WHERE username=?", newUsername, oldUsername)
	if err != nil {
		return err
	}
	return nil
}

// Function changes user's password.
// ErrInvalidPassword returned if password is invalid
// ErrUserNotExists returned if user does not exist
func ChangeUserPasswd(db *sql.DB, username string, newPasswd string) error {
	ok, err := isUserExists(db, username)
	if err != nil {
		return err
	} else if !ok {
		return types.ErrUserNotExists{Message: "Error: changeUserPasswd: User does not exist"}
	}
	if !isValidPasswd(newPasswd) {
		return types.ErrInvalidNameOrPasswd{Message: "Error: changeUserPasswd: Invalid password"}
	}

	userPasswdHash, err := bcrypt.GenerateFromPassword([]byte(newPasswd), 12)
	if err != nil {
		return err
	}
	_, err = db.Exec("UPDATE users SET passwd_hash=? WHERE username=?", string(userPasswdHash), username)
	if err != nil {
		return err
	}
	return nil
}

// Changes user's is_banned field to 1
// Returns ErrUserStatusUnchanged if user already banned
// Returns ErrUserNotExists if user does not exist
func BanUser(db *sql.DB, username string) error {
	// Check if user does not exist or is banned
	banned, err := IsBannedUser(db, username)
	if err != nil {
		if _, ok := err.(types.ErrUserNotExists); ok {
			return types.ErrUserNotExists{Message: "BanUser: User does not exist"}
		}
		return err
	}
	if banned {
		return types.ErrUserStatusUnchanged{Message: "BanUser: Attempted to ban a banned user"}
	}

	// change is_banned to 1
	_, err = db.Exec("UPDATE users SET is_banned=1 WHERE username=?", username)
	if err != nil {
		return err
	}
	return nil
}

// Changes user's is_banned field to 0
// Returns ErrUserStatusUnchanged if user is not banned
// Returns ErrUserNotExists if user does not exist
func UnbanUser(db *sql.DB, username string) error {
	// Check if user does not exist or is not banned
	banned, err := IsBannedUser(db, username)
	if err != nil {
		if _, ok := err.(types.ErrUserNotExists); ok {
			return types.ErrUserNotExists{Message: "UnbanUser: User does not exist"}
		}
		return err
	}
	if !banned {
		return types.ErrUserStatusUnchanged{Message: "UnbanUser: Attempted to unban a non-banned user"}
	}

	// change is_banned to 0
	_, err = db.Exec("UPDATE users SET is_banned=0 WHERE username=?", username)
	if err != nil {
		return err
	}
	return nil
}

// Changes user's is_admin field to 1
// Returns ErrUserStatusUnchanged if user is already an admin
// Returns ErrUserNotExists if user does not exist
func EnableUserAdmin(db *sql.DB, username string) error {
	// Check if user does not exist or is an admin
	admin, err := IsAdmin(db, username)
	if err != nil {
		if _, ok := err.(types.ErrUserNotExists); ok {
			return types.ErrUserNotExists{Message: "EnableUserAdmin: User does not exist"}
		}
		return err
	}
	if admin {
		return types.ErrUserStatusUnchanged{Message: "EnableUserAdmin: Attempted to enable admin status for an admin"}
	}

	// is_admin changed to 1
	_, err = db.Exec("UPDATE users SET is_admin=1 WHERE username=?", username)
	if err != nil {
		return err
	}
	return nil
}

// Changes user's is_admin field to 0
// Returns ErrUserStatusUnchanged if user is already an admin
// Returns ErrUserNotExists if user does not exist
func DisableUserAdmin(db *sql.DB, username string) error {
	// Check if user does not exist or is an admin
	admin, err := IsAdmin(db, username)
	if err != nil {
		if _, ok := err.(types.ErrUserNotExists); ok {
			return types.ErrUserNotExists{Message: "DisableUserAdmin: User does not exist"}
		}
		return err
	}
	if !admin {
		return types.ErrUserStatusUnchanged{Message: "DisableUserAdmin: Attempted to disable admin status for non-admin"}
	}

	// is_admin changed to 0
	_, err = db.Exec("UPDATE users SET is_admin=0 WHERE username=?", username)
	if err != nil {
		return err
	}
	return nil
}

func isValidPasswd(password string) bool { // TODO: add better password validity check
	if len(password) < 4 || len(password) > 100 {
		return false
	}
	return true
}
func isValidUsername(username string) bool { // TODO: add regex to check character validity
	if len(username) < 2 || len(username) > 100 {
		return false
	}
	return true
}

// Function checks if user exists, returns boolean
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
