package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Knetic/govaluate"
)

// TODO:
// ADD PASSWORD CHECK

func main() {
	settings := Settings{
		LogLevel:   3,
		LogToFile:  false,
		DBName:     "net_calc_db",
		DBUsername: "root",
		DBPassword: "10740",
	}
	db, err := initDB(settings)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(db)

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
	if fmt.Sprint(result) == "<nil>" {
		return "", nil
	}
	return fmt.Sprint(result), nil
}
