package main

import (
	"database/sql"
	"encoding/base64"
	"io"
	"log"
	"net/http"
)

func newLoginHandler(settings *Settings, db *sql.DB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

	}
}

func newRegisterHandler(settings *Settings, db *sql.DB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

	}
}

func newCalcHandler(settings *Settings) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Bad request", http.StatusBadRequest)
			if settings.LogLevel >= 1 {
				log.Println("Bad request")
			}
			return
		}
		defer r.Body.Close()
		encodedExp := r.URL.Query().Get("exp")
		if encodedExp == "" {
			http.Error(w, "exp parameter missing", http.StatusBadRequest)
			if settings.LogLevel >= 1 {
				log.Println("exp parameter missing")
			}
			return
		}

		expBytes, err := base64.URLEncoding.DecodeString(encodedExp)
		if err != nil {
			http.Error(w, "Expression could not be decoded correctly", http.StatusBadRequest)
			if settings.LogLevel >= 1 {
				log.Println("Expression could not be decoded correctly")
			}
			return
		}
		exp := string(expBytes)
		result, err := calcExpression(exp)
		if err != nil {
			http.Error(w, "Invalid expression", http.StatusBadRequest)
			if settings.LogLevel >= 1 {
				log.Println("Invalid expression")
			}
			return
		}
		log.Println("Calculated expression:", exp, "result:", result)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if _, err := io.WriteString(w, result); err != nil {
			if settings.LogLevel >= 1 {
				log.Println(err)
			}
		}
	}
}
