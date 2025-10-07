package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Knetic/govaluate"
)

// TODO:
// Add authentication and admin functionality
// Add logging
// Add ability to get database credentials from environment variables
// Add ability to specify custom port for database
// Rewrite processArgs to use flag package
// use toml or something like that for config file
// LogToFile setting is unnecessary, log file has to be used only if path to is it given
// Maybe split program into packages

func main() {
	settings := genSettings()
	db, err := initDB(settings)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/register", newRegisterHandler(&settings, db))
	http.HandleFunc("/login", newLoginHandler(&settings, db))
	http.HandleFunc("/calculate", newCalcHandler(&settings))
	fmt.Println("Server running on port 8080")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func calcExpression(expression string) (string, error) {
	govalExp, err := govaluate.NewEvaluableExpression(expression)
	if err != nil {
		return "", err
	}
	result, err := govalExp.Evaluate(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: calcExpression:", err)
	}
	if fmt.Sprint(result) == "<nil>" {
		return "", nil
	}
	return fmt.Sprint(result), nil
}

func Ptr[T any](v T) *T {
	return &v
}
