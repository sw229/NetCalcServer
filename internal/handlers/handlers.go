package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/sw229/netCalcServer/internal/auth"
	"github.com/sw229/netCalcServer/internal/database"
	"github.com/sw229/netCalcServer/internal/logging"
	"github.com/sw229/netCalcServer/internal/types"

	"github.com/Knetic/govaluate"
)

// Function handles health check requests
// Returns a map with 2 keys: db - database accessibility, server - server status (now it is always ok)
// Possible values: ok, error
func NewPingHandler(db *sql.DB, lg logging.Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			lg.LogMsg("non-GET request to /ping", logging.LogInfo)
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
		lg.LogMsg("Ping request recieved", logging.LogInfo)
		if checks["db"] == "error" {
			lg.LogMsg(fmt.Sprintf("Error accessing database: %s", err), logging.LogError)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(checks)
	}
}

// Function handles login requests, generates jwt tokens
// Token validation is not implemented, so this is useless
func NewLoginHandler(db *sql.DB, lg logging.Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if login request method is correct
		if r.Method != http.MethodPost {
			lg.LogMsg("non-POST request to /login", logging.LogInfo)
			http.Error(w, "Bad request", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		// Decode body into UserCredentials struct. Maybe use Authorization handler instead?
		var user types.UserCredentials
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			lg.LogMsg("Could not decode request body", logging.LogInfo)
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Check if username and password are correct
		// isCorrectPassword returns ErrUserNotExists if username is invalid
		// or false with nil error if password is invalid
		// Any other error is an issue while accessing database
		if ok, err := database.IsCorrectPassword(db, user); !ok {
			if _, ok := err.(types.ErrUserNotExists); ok {
				lg.LogMsg(fmt.Sprintf("Attempted login with invalid username: %s", user.Username), logging.LogInfo)
				http.Error(w, "Invalid username", http.StatusUnauthorized)
				return
			}
			if err != nil {
				lg.LogMsg(fmt.Sprintf("Error reading database: %s", err), logging.LogError)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		// Token is generated from user credentials and secret
		token, err := auth.GenJwt(user, auth.Secret)
		if err != nil {
			lg.LogMsg("Error while generating jwt token", logging.LogError)
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
func NewRegisterHandler(db *sql.DB, lg logging.Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			lg.LogMsg("non-POST request to /register", logging.LogInfo)
			http.Error(w, "Bad request", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		var user types.UserCredentials

		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			lg.LogMsg("Could not decode request body", logging.LogInfo)
			http.Error(w, fmt.Sprintf("Invalid request body: %s", err), http.StatusBadRequest)
			return
		}

		if err := database.AddUser(db, user); err != nil {
			if _, ok := err.(types.ErrUserExists); ok {
				lg.LogMsg(fmt.Sprintf("Attempted to add existing user %s", user.Username), logging.LogInfo)
				http.Error(w, "User already exists", http.StatusBadRequest)
				return
			} else if _, ok := err.(types.ErrInvalidNameOrPasswd); ok {
				lg.LogMsg(fmt.Sprintf("Attempted to add existing user %s", user.Username), logging.LogInfo)
				http.Error(w, "Invalid username or password", http.StatusBadRequest)
				return
			}
			lg.LogMsg(fmt.Sprintf("Error adding user to database: %s", err), logging.LogError)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if _, err := io.WriteString(w, "success"); err != nil {
			lg.LogMsg(fmt.Sprintf("Unable to send response: %s", err), logging.LogInfo)
		}
	}
}

// Handles user deletion request
func NewDeleteHandler(db *sql.DB, lg logging.Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			lg.LogMsg("non-DELETE request to /delete", logging.LogInfo)
			http.Error(w, "Bad request", http.StatusMethodNotAllowed)
		}

		usernameBytes, err := io.ReadAll(r.Body)
		if err != nil {
			lg.LogMsg("Could not decode request body", logging.LogInfo)
			http.Error(w, fmt.Sprintf("Invalid request body: %s", err), http.StatusBadRequest)
			return
		}
		username := string(usernameBytes)

		err = database.DeleteUser(db, username)
		if _, ok := err.(types.ErrUserNotExists); ok {
			if _, err := io.WriteString(w, "User does not exist"); err != nil {
				lg.LogMsg(fmt.Sprintf("User deletion request failed: %s", err), logging.LogInfo)
				return
			}
			return
		} else if err != nil {
			lg.LogMsg(fmt.Sprintf("Error deleting user: %s", err), logging.LogError)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if _, err := io.WriteString(w, "success"); err != nil {
			lg.LogMsg(fmt.Sprintf("Unable to send response: %s", err), logging.LogInfo)
		}
	}
}

// Handles a POST request containing userToBan struct (2 fields - username and ban)
func NewBanHandler(db *sql.DB, lg logging.Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// if request is not POST, client recieves an error
		if r.Method != http.MethodPost {
			lg.LogMsg("non-POST request to /admin/ban", logging.LogInfo)
			http.Error(w, "Bad request", http.StatusMethodNotAllowed)
		}

		// Deserialize userToBan struct
		var user types.UserToBan
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			lg.LogMsg("Could not decode request body", logging.LogInfo)
			http.Error(w, fmt.Sprintf("Invalid request body: %s", err), http.StatusBadRequest)
			return
		}

		// Check if user is banned/unbanned already
		banned, err := database.IsBannedUser(db, user.Username)
		if err != nil {
			if _, ok := err.(types.ErrUserNotExists); ok {
				if user.NewBanStatus {
					lg.LogMsg("Attempted to ban non-existing user", logging.LogInfo)
				} else {
					lg.LogMsg("Attempted to unban non-existing user", logging.LogInfo)
				}
				if _, err := io.WriteString(w, "User does not exist"); err != nil {
					lg.LogMsg(fmt.Sprintf("User ban request failed: %s", err), logging.LogInfo)
					return
				}
				return
			}
			if user.NewBanStatus {
				lg.LogMsg(fmt.Sprintf("Error banning user: %s", err), logging.LogError)
			} else {
				lg.LogMsg(fmt.Sprintf("Error unbanning user: %s", err), logging.LogError)
			}

			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Check if user is already banned/unbanned
		if user.NewBanStatus == banned {
			if _, err := io.WriteString(w, "Nothing changed"); err != nil {
				lg.LogMsg(fmt.Sprintf("Could not send response ti client: %s", err), logging.LogInfo)
				return
			}
			if banned {
				lg.LogMsg(fmt.Sprintf("Attempted to ban a banned user: %s", user.Username), logging.LogInfo)
			} else {
				lg.LogMsg(fmt.Sprintf("Attempted to unban a non-banned user: %s", user.Username), logging.LogInfo)
			}
			return
		}
		// Ban user
		if user.NewBanStatus {
			if err := database.BanUser(db, user.Username); err != nil {
				lg.LogMsg(fmt.Sprintf("Error unbanning user: %s", err), logging.LogError)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			lg.LogMsg(fmt.Sprintf("User %s banned", user.Username), logging.LogInfo)
			if _, err := io.WriteString(w, fmt.Sprintf("User %s banned", user.Username)); err != nil {
				lg.LogMsg(fmt.Sprintf("Could not send response to client: %s", err), logging.LogInfo)
			}
			return
		}
		// Unban user
		if err := database.UnbanUser(db, user.Username); err != nil {
			lg.LogMsg(fmt.Sprintf("Error unbanning user: %s", err), logging.LogError)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		lg.LogMsg(fmt.Sprintf("User %s unbanned", user.Username), logging.LogInfo)
		if _, err := io.WriteString(w, fmt.Sprintf("User %s unbanned", user.Username)); err != nil {
			lg.LogMsg(fmt.Sprintf("Could not send response to client: %s", err), logging.LogInfo)
		}
	}
}

// Handles a POST request containing changeAdminStatus struct (2 fields - username and new status)
func NewSetAdminHandler(db *sql.DB, lg logging.Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			lg.LogMsg("non-POST request to /admin/adminstatus", logging.LogInfo)
			http.Error(w, "Bad request", http.StatusMethodNotAllowed)
		}
	}
}

// Handles calculation requests
// Expression is sent in plain text
// Result is also sent in plain text
func NewCalcHandler(db *sql.DB, lg logging.Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			lg.LogMsg("Incoming calculation request failed: bad request", logging.LogInfo)
			http.Error(w, "Bad request", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		/* This part is partially finished logic for validating jwt tokens
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			lg.LogMsg("Incomming calculation request failed: invalid authorization header format", LogInfo)
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
			lg.LogMsg("Incoming calculation request failed: expression parameter missing", logging.LogInfo)
			return
		}

		expBytes, err := base64.URLEncoding.DecodeString(encodedExp)
		if err != nil {
			http.Error(w, "Expression could not be decoded correctly", http.StatusBadRequest)
			lg.LogMsg("Incoming calculaton request failed: bad expression encoding", logging.LogInfo)
			return
		}
		exp := string(expBytes)
		result, err := CalcExpression(exp, lg)
		if err != nil {
			http.Error(w, "Invalid expression", http.StatusBadRequest)
			lg.LogMsg("Incoming calculation request failed: invalid expression", logging.LogInfo)
			return
		}
		log.Println("Calculated expression:", exp, "result:", result)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if _, err := io.WriteString(w, result); err != nil {
			lg.LogMsg(fmt.Sprintf("Incoming calculation request failed: %s", err), logging.LogInfo)
		}
	}
}

// Function handles a request for data about users
// Usernames are given as users query string, must be comma separated
// If no usernames given, a list of all users is returned
// Only GET requests allowed
func NewGetUsersHandler(db *sql.DB, lg logging.Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			lg.LogMsg("Incoming user data request failed: invalid request method", logging.LogInfo)
			http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		names := r.URL.Query().Get("users")
		var users []types.DisplayedUserData
		var err error
		if names == "" {
			users, err = database.ListAllUsers(db)
			if err != nil {
				lg.LogMsg(fmt.Sprintf("Error accessing user database: %s", err), logging.LogError)
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}
			lg.LogMsg("Administrator requested list of all users", logging.LogInfo)
		} else {
			namesSlice := strings.Split(names, ",")
			users, err = database.ListUsers(db, namesSlice)
			if err != nil {
				lg.LogMsg(fmt.Sprintf("Error accessing user database: %s", err), logging.LogError)
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}
			lg.LogMsg(fmt.Sprintf("Administrator requested list of users: %s", names), logging.LogInfo)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	}
}

func CalcExpression(expression string, lg logging.Logging) (string, error) {
	govalExp, err := govaluate.NewEvaluableExpression(expression)
	if err != nil {
		return "", err
	}
	result, err := govalExp.Evaluate(nil)
	if err != nil {
		lg.LogMsg(fmt.Sprintf("Colud not calculate expression %s: %s", expression, err), logging.LogWarning)
	}
	if fmt.Sprint(result) == "<nil>" {
		lg.LogMsg(fmt.Sprintf("Colud not calculate expression %s: result is nil", expression), logging.LogWarning)
	}
	return fmt.Sprint(result), nil
}
