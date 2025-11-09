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

// Handles a POST request containing userToBan struct (2 fields - username and new ban status)
func NewBanHandler(db *sql.DB, lg logging.Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// if request is not POST, client recieves an error
		if r.Method != http.MethodPost {
			lg.LogMsg("non-POST request to /admin/ban", logging.LogInfo)
			http.Error(w, "Bad request", http.StatusMethodNotAllowed)
			return
		}

		// Deserialize userToBan struct
		var user types.UserToBan
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			lg.LogMsg("Could not decode request body", logging.LogInfo)
			http.Error(w, fmt.Sprintf("Invalid request body: %s", err), http.StatusBadRequest)
			return
		}

		// Ban user
		// database.BanUser also checks if user exists or is already banned
		// handleBanError is used to handle these errors
		if user.NewBanStatus {
			if err := database.BanUser(db, user.Username); err != nil {
				if handleBanError(err, lg, w, true) {
					return
				}
				lg.LogMsg(fmt.Sprintf("Error banning user: %s", err), logging.LogError)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			lg.LogMsg(fmt.Sprintf("User %s banned", user.Username), logging.LogInfo)
			sendResponse(fmt.Sprintf("User %s banned", user.Username), w, lg)
			return
		}
		// Unban user
		// database.UnbanUser also checks if user exists or is not banned
		if err := database.UnbanUser(db, user.Username); err != nil {
			if handleBanError(err, lg, w, false) {
				return
			}
			lg.LogMsg(fmt.Sprintf("Error unbanning user: %s", err), logging.LogError)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		lg.LogMsg(fmt.Sprintf("User %s unbanned", user.Username), logging.LogInfo)
		sendResponse(fmt.Sprintf("User %s unbanned", user.Username), w, lg)
	}
}

// Function checks the error returned by database.BanUser, returns bool if successful
// If error is ErrUserNotExists or ErrUserStatusUnchanged function returns true,
// corresponding response is sent to the client, also everything is logged.
// If it is any other error, function returns false
func handleBanError(err error, lg logging.Logging, w http.ResponseWriter, newBanStatus bool) bool {
	switch err.(type) {
	case types.ErrUserNotExists:
		if newBanStatus {
			lg.LogMsg("Attempted to ban a non-existing user", logging.LogInfo)
		} else {
			lg.LogMsg("Attempted to unban a non-existing user", logging.LogInfo)
		}
		sendResponse("User does not exist", w, lg)
		return true
	case types.ErrUserStatusUnchanged:
		if newBanStatus {
			lg.LogMsg("Attempted to ban a banned user", logging.LogInfo)
		} else {
			lg.LogMsg("Attempted to unban a non-banned user", logging.LogInfo)
		}
		sendResponse("Nothing changed", w, lg)
		return true
	}
	return false
}

// Handles a POST request containing changeAdminStatus struct (2 fields - username and new status)
func NewSetAdminHandler(db *sql.DB, lg logging.Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// If method is not POST, client recieves an error
		if r.Method != http.MethodPost {
			lg.LogMsg("non-POST request to /admin/adminstatus", logging.LogInfo)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Deserialize changeAdmisStatus struct
		var user types.ChangeAdminStatus
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			lg.LogMsg("Could not decode request body", logging.LogInfo)
			http.Error(w, fmt.Sprintf("Invalid request body: %s", err), http.StatusBadRequest)
			return
		}

		// Enable admin status.	database.EnableUserAdmin also checks if uder does not exist or is already an admin.
		// handleAdminStatusError is used tho handle these errors.
		if user.NewAdminStatus {
			if err := database.EnableUserAdmin(db, user.Username); err != nil {
				if handleAdminStatusError(err, lg, w, true) {
					return
				}
				lg.LogMsg(fmt.Sprintf("Error enabling admin status for user: %s", err), logging.LogError)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			lg.LogMsg(fmt.Sprintf("Enabled admin status for user %s", user.Username), logging.LogInfo)
			sendResponse(fmt.Sprintf("Enabled admin status for user %s", user.Username), w, lg)
			return
		}
		// Disable admin staatus
		if err := database.DisableUserAdmin(db, user.Username); err != nil {
			if handleAdminStatusError(err, lg, w, false) {
				return
			}
			lg.LogMsg(fmt.Sprintf("Error disabling admin status for user: %s", err), logging.LogError)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		lg.LogMsg(fmt.Sprintf("Disabled admin status for user %s", user.Username), logging.LogInfo)
		sendResponse(fmt.Sprintf("Disabled admin status for user %s", user.Username), w, lg)
	}
}

// Function checks the error returned by database.EnableUserAdmin, returns bool if successful
// If error is ErrUserNotExists or ErrUserStatusUnchanged function returns true,
// corresponding response is sent to the client, also everything is logged.
// If it is any other error, function returns false
func handleAdminStatusError(err error, lg logging.Logging, w http.ResponseWriter, newAdminStatus bool) bool {
	switch err.(type) {
	case types.ErrUserNotExists:
		if newAdminStatus {
			lg.LogMsg("Attempted to enable admin status for a non-existing user", logging.LogInfo)
		} else {
			lg.LogMsg("Attempted to disable admin status for a non-existing user", logging.LogInfo)
		}
		sendResponse("User does not exist", w, lg)
		return true
	case types.ErrUserStatusUnchanged:
		if newAdminStatus {
			lg.LogMsg("Attempted to ebable admin status for an admin", logging.LogInfo)
		} else {
			lg.LogMsg("Attempted to disable admin status for a non-admin", logging.LogInfo)
		}
		sendResponse("Nothing changed", w, lg)
		return true
	}
	return false
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
		result, err := calcExpression(exp, lg)
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

// Function sends given message to the client as http response, logs any errors.
func sendResponse(message string, w http.ResponseWriter, lg logging.Logging) {
	if _, err := io.WriteString(w, message); err != nil {
		lg.LogMsg(fmt.Sprintf("Unable to send response to client: %s", err), logging.LogInfo)
	}
}

// Function calculates the result of an expressin passed as string, logs any errors
// Result is returned as string
func calcExpression(expression string, lg logging.Logging) (string, error) {
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
