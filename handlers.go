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

func newLoginHandler(settings *Settings, db *sql.DB, lg Logging) func(w http.ResponseWriter, r *http.Request) {
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
				lg.logMsg(fmt.Sprintf("Error reading database: %s", err), LogInfo)
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
func newRegisterHandler(settings *Settings, db *sql.DB, lg Logging) func(w http.ResponseWriter, r *http.Request) {
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
			}
			lg.logMsg(fmt.Sprintf("Error adding user to database: %s", err), LogError)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if _, err := io.WriteString(w, "success"); err != nil {
			lg.logMsg(fmt.Sprintf("User register request failed: %s", err), LogInfo)
		}
	}
}

func newCalcHandler(settings *Settings, lg Logging) func(w http.ResponseWriter, r *http.Request) {
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
