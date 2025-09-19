package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Knetic/govaluate"
)

func main() {
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/calculate", calcHandler)
	fmt.Println("Server running on port 8080")
	err := http.ListenAndServe(":8080", nil)
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
	if fmt.Sprint(result) == "<nil>" {
		return "", nil
	}
	return fmt.Sprint(result), nil
}
