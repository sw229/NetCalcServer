package main

import "time"

// LogLevel 0 - logs nothing
// Loglevel 1 - logs errors
// Loglevel 2 - logs errors, warnings
// LogLevel 3 - logs user info (login, register), errors, warnings
// LogLevel 4 - logs info, errors, warnings, all operations
type Settings struct {
	ServerPort  *string
	LogLevel    *int
	LogToFile   *bool
	LogFilePath *string
	DBName      *string
	DBUsername  *string
	DBPassword  *string
}

// Structure to store user credentials before an entry
// for the user is created in the database
type UserCredentials struct {
	Username string
	Password string
	IsAdmin  bool
}

// Structure for user data sent to admin client
type DisplayedUserData struct {
	Username    string    `json:"username"`
	DateCreated time.Time `json:"created"`
	IsAdmin     bool      `json:"admin"`
	IsBanned    bool      `json:"banned"`
}

// Struct to change user ban status
// If newBanStatus == true, user is banned
// Else user is unbanned
type UserToBan struct {
	Username     string `json:"username"`
	NewBanStatus bool   `json:"ban"`
}

// Struct to change user admin status
// If NewAdminStatus == true, user becomes admin
// Else admin status is disabled
type ChangeAdminStatus struct {
	Username       string `json:"username"`
	NewAdminStatus bool   `json:"admin"`
}

// Returned if requested user does not exist
type ErrUserNotExists struct {
	message string
}

func (err ErrUserNotExists) Error() string {
	return err.message
}

// Returned if user with specific username already exists
type ErrUserExists struct {
	message string
}

func (err ErrUserExists) Error() string {
	return err.message
}

// Returned if username or password are invalid
type ErrInvalidNameOrPasswd struct {
	message string
}

func (err ErrInvalidNameOrPasswd) Error() string {
	return err.message
}

// Returned if file is invalid
type ErrInvalidFile struct {
	message string
}

func (err ErrInvalidFile) Error() string {
	return err.message
}
