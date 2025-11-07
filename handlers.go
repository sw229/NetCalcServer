package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/Knetic/govaluate"
)

// Function handles health check requests
// Returns a map with 2 keys: db - database accessibility, server - server status (now it is always ok)
// Possible values: ok, error
func newPingHandler(db *sql.DB, lg Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			lg.logMsg("non-GET request to /ping", LogInfo)
			http.Error(w, "Bad request", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		checks := make(map[string]string)

		err := db.Ping()
		if err != nil {
			checks["db"] = "error"
		} else {
			checks["db"] = "ok"
		}
		checks["server"] = "ok"
		lg.logMsg("Ping request recieved", LogInfo)
		if checks["db"] == "error" {
			lg.logMsg(fmt.Sprintf("Error accessing database: %s", err), LogError)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(checks)
	}
}

// Function handles login requests, generates jwt tokens
// Token validation is not implemented, so this is useless
func newLoginHandler(db *sql.DB, lg Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if login request method is correct
		if r.Method != http.MethodPost {
			lg.logMsg("non-POST request to /login", LogInfo)
			http.Error(w, "Bad request", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		// Decode body into UserCredentials struct. Maybe use Authorization handler instead?
		var user UserCredentials
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			lg.logMsg("Could not decode request body", LogInfo)
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Check if username and password are correct
		// isCorrectPassword returns ErrUserNotExists if username is invalid
		// or false with nil error if password is invalid
		// Any other error is an issue while accessing database
		if ok, err := isCorrectPassword(db, user); !ok {
			if _, ok := err.(ErrUserNotExists); ok {
				lg.logMsg(fmt.Sprintf("Attempted login with invalid username: %s", user.Username), LogInfo)
				http.Error(w, "Invalid username", http.StatusUnauthorized)
				return
			}
			if err != nil {
				lg.logMsg(fmt.Sprintf("Error reading database: %s", err), LogError)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		// Token is generated from user credentials and secret
		token, err := genJwt(user, secret)
		if err != nil {
			lg.logMsg("Error while generating jwt token", LogError)
			http.Error(w, "Error generating token", http.StatusInternalServerError)
			return
		}

		// Response is created
		response := map[string]string{
			"token":   token,
			"message": "login successful",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// Function adds new user to the database
// User data is stored in POST request body in json-encoded UserCredentials struct
func newRegisterHandler(db *sql.DB, lg Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			lg.logMsg("non-POST request to /register", LogInfo)
			http.Error(w, "Bad request", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		var user UserCredentials

		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			lg.logMsg("Could not decode request body", LogInfo)
			http.Error(w, fmt.Sprintf("Invalid request body: %s", err), http.StatusBadRequest)
			return
		}

		if err := addUser(db, user); err != nil {
			if _, ok := err.(ErrUserExists); ok {
				lg.logMsg(fmt.Sprintf("Attempted to add existing user %s", user.Username), LogInfo)
				http.Error(w, "User already exists", http.StatusBadRequest)
				return
			} else if _, ok := err.(ErrInvalidNameOrPasswd); ok {
				lg.logMsg(fmt.Sprintf("Attempted to add existing user %s", user.Username), LogInfo)
				http.Error(w, "Invalid username or password", http.StatusBadRequest)
				return
			}
			lg.logMsg(fmt.Sprintf("Error adding user to database: %s", err), LogError)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if _, err := io.WriteString(w, "success"); err != nil {
			lg.logMsg(fmt.Sprintf("Unable to send response: %s", err), LogInfo)
		}
	}
}

// Handles user deletion request
func newDeleteHandler(db *sql.DB, lg Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			lg.logMsg("non-DELETE request to /delete", LogInfo)
			http.Error(w, "Bad request", http.StatusMethodNotAllowed)
		}

		usernameBytes, err := io.ReadAll(r.Body)
		if err != nil {
			lg.logMsg("Could not decode request body", LogInfo)
			http.Error(w, fmt.Sprintf("Invalid request body: %s", err), http.StatusBadRequest)
			return
		}
		username := string(usernameBytes)

		err = deleteUser(db, username)
		if _, ok := err.(ErrUserNotExists); ok {
			if _, err := io.WriteString(w, "User does not exist"); err != nil {
				lg.logMsg(fmt.Sprintf("User deletion request failed: %s", err), LogInfo)
				return
			}
			return
		} else if err != nil {
			lg.logMsg(fmt.Sprintf("Error deleting user: %s", err), LogError)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if _, err := io.WriteString(w, "success"); err != nil {
			lg.logMsg(fmt.Sprintf("Unable to send response: %s", err), LogInfo)
		}
	}
}

// Handles a POST request containing userToBan struct (2 fields - username and ban)
func newBanHandler(db *sql.DB, lg Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			lg.logMsg("non-POST request to /admin/ban", LogInfo)
			http.Error(w, "Bad request", http.StatusMethodNotAllowed)
		}

		// Deserialize userToBan struct
		var user UserToBan
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			lg.logMsg("Could not decode request body", LogInfo)
			http.Error(w, fmt.Sprintf("Invalid request body: %s", err), http.StatusBadRequest)
			return
		}

		// Check if user is banned/unbanned already
		banned, err := isBannedUser(db, user.Psername)
		if err != nil {
			if _, ok := err.(ErrUserNotExists); ok {
				if user.Ban {
					lg.logMsg("Attempted to ban non-existing user", LogInfo)
				} else {
					lg.logMsg("Attempted to unban non-existing user", LogInfo)
				}
				if _, err := io.WriteString(w, "User does not exist"); err != nil {
					lg.logMsg(fmt.Sprintf("User ban request failed: %s", err), LogInfo)
					return
				}
				return
			}
			if user.Ban {
				lg.logMsg(fmt.Sprintf("Error banning user: %s", err), LogError)
			} else {
				lg.logMsg(fmt.Sprintf("Error unbanning user: %s", err), LogError)
			}

			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if user.Ban == banned {
			if _, err := io.WriteString(w, "Nothing changed"); err != nil {
				lg.logMsg(fmt.Sprintf("User ban request failed: %s", err), LogInfo)
				return
			}
			if banned {
				lg.logMsg(fmt.Sprintf("Attempted to ban a banned user: %s", user.Psername), LogInfo)
			} else {
				lg.logMsg(fmt.Sprintf("Attempted to unban a non-banned user: %s", user.Psername), LogInfo)
			}
			return
		}
		// ADD user ban/unban logic. At this point in function user is valid and ban/unban operation is necessary
		if user.Ban {
			if err := banUser(db, user.Psername); err != nil {
				lg.logMsg(fmt.Sprintf("Error unbanning user: %s", err), LogError)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			lg.logMsg(fmt.Sprintf("User %s banned", user.Psername), LogInfo)
			if _, err := io.WriteString(w, fmt.Sprintf("User %s banned", user.Psername)); err != nil {
				lg.logMsg(fmt.Sprintf("Could not send response to client: %s", err), LogInfo)
			}
			return
		}
		if err := unbanUser(db, user.Psername); err != nil {
			lg.logMsg(fmt.Sprintf("Error unbanning user: %s", err), LogError)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		lg.logMsg(fmt.Sprintf("User %s unbanned", user.Psername), LogInfo)
		if _, err := io.WriteString(w, fmt.Sprintf("User %s unbanned", user.Psername)); err != nil {
			lg.logMsg(fmt.Sprintf("Could not send response to client: %s", err), LogInfo)
		}
	}
}

// Handles calculation requests
// Expression is sent in plain text
// Result is also sent in plain text
func newCalcHandler(db *sql.DB, lg Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			lg.logMsg("Incoming calculation request failed: bad request", LogInfo)
			http.Error(w, "Bad request", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		/* This part is partially finished logic for validating jwt tokens
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			lg.logMsg("Incomming calculation request failed: invalid authorization header format", LogInfo)
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "bearer")
		*/
		encodedExp := r.URL.Query().Get("exp")
		if encodedExp == "" {
			http.Error(w, "exp parameter missing", http.StatusBadRequest)
			lg.logMsg("Incoming calculation request failed: expression parameter missing", LogInfo)
			return
		}

		expBytes, err := base64.URLEncoding.DecodeString(encodedExp)
		if err != nil {
			http.Error(w, "Expression could not be decoded correctly", http.StatusBadRequest)
			lg.logMsg("Incoming calculaton request failed: bad expression encoding", LogInfo)
			return
		}
		exp := string(expBytes)
		result, err := calcExpression(exp, lg)
		if err != nil {
			http.Error(w, "Invalid expression", http.StatusBadRequest)
			lg.logMsg("Incoming calculation request failed: invalid expression", LogInfo)
			return
		}
		log.Println("Calculated expression:", exp, "result:", result)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if _, err := io.WriteString(w, result); err != nil {
			lg.logMsg(fmt.Sprintf("Incoming calculation request failed: %s", err), LogInfo)
		}
	}
}

// Function handles a request for data about users
// Usernames are given as users query string, must be comma separated
// If no usernames given, a list of all users is returned
// Only GET requests allowed
func newGetUsersHandler(db *sql.DB, lg Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			lg.logMsg("Incoming user data request failed: invalid request method", LogInfo)
			http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		names := r.URL.Query().Get("users")
		var users []DisplayedUserData
		var err error
		if names == "" {
			users, err = listAllUsers(db)
			if err != nil {
				lg.logMsg(fmt.Sprintf("Error accessing user database: %s", err), LogError)
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}
			lg.logMsg("Administrator requested list of all users", LogInfo)
		} else {
			namesSlice := strings.Split(names, ",")
			users, err = listUsers(db, namesSlice)
			if err != nil {
				lg.logMsg(fmt.Sprintf("Error accessing user database: %s", err), LogError)
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}
			lg.logMsg(fmt.Sprintf("Administrator requested list of users: %s", names), LogInfo)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	}
}

func calcExpression(expression string, lg Logging) (string, error) {
	govalExp, err := govaluate.NewEvaluableExpression(expression)
	if err != nil {
		return "", err
	}
	result, err := govalExp.Evaluate(nil)
	if err != nil {
		lg.logMsg(fmt.Sprintf("Colud not calculate expression %s: %s", expression, err), LogWarning)
	}
	if fmt.Sprint(result) == "<nil>" {
		lg.logMsg(fmt.Sprintf("Colud not calculate expression %s: result is nil", expression), LogWarning)
	}
	return fmt.Sprint(result), nil
}
