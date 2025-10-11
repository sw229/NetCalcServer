package main

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

type UserCredentials struct {
	Username string
	Password string
	IsAdmin  bool
}

// Returned if user with specific username already exists
type ErrUserNotExists struct {
	message string
}

func (err ErrUserNotExists) Error() string {
	return err.message
}

// Returned if user with specific username does not exist
type ErrUserExists struct {
	message string
}

func (err ErrUserExists) Error() string {
	return err.message
}

type ErrInvalidPassword struct {
	message string
}

func (err ErrInvalidPassword) Error() string {
	return err.message
}

// Returned if file is invalid
type ErrInvalidFile struct {
	message string
}

func (err ErrInvalidFile) Error() string {
	return err.message
}
