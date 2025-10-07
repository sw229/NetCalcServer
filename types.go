package main

// LogLevel 0 - logs nothing
// Loglevel 1 - logs errors
// LogLevel 2 - logs user login, register, errors
// LogLevel 3 - logs user login, register, errors, all operations
type Settings struct {
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

// Returned if config file is invalid
type ErrInvalidConfigFile struct {
	message string
}

func (err ErrInvalidConfigFile) Error() string {
	return err.message
}
