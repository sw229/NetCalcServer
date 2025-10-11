package main

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/Knetic/govaluate"
)

func newLoginHandler(settings *Settings, db *sql.DB, lg Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

	}
}

func newRegisterHandler(settings *Settings, db *sql.DB, lg Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

	}
}

func newCalcHandler(settings *Settings, lg Logging) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Bad request", http.StatusBadRequest)
			lg.logMsg("Incoming calculation request failed: bad request", LogWarning)
			return
		}
		defer r.Body.Close()
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
