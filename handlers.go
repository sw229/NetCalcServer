package main

import (
	"encoding/base64"
	"io"
	"log"
	"net/http"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {

}

func registerHandler(w http.ResponseWriter, r *http.Request) {

}

func calcHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Bad request", http.StatusBadRequest)
		log.Println("Bad request")
		return
	}
	defer r.Body.Close()
	encodedExp := r.URL.Query().Get("exp")
	if encodedExp == "" {
		http.Error(w, "exp parameter missing", http.StatusBadRequest)
		log.Println("exp parameter missing")
		return
	}

	expBytes, err := base64.URLEncoding.DecodeString(encodedExp)
	if err != nil {
		http.Error(w, "Expression could not be decoded correctly", http.StatusBadRequest)
		log.Println("Expression could not be decoded correctly")
		return
	}
	exp := string(expBytes)
	result, err := calcExpression(exp)
	if err != nil {
		http.Error(w, "Invalid expression", http.StatusBadRequest)
		log.Println("Invalid expression")
		return
	}
	log.Println("Calculated expression:", exp, "result:", result)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if _, err := io.WriteString(w, result); err != nil {
		log.Println(err)
	}
}
