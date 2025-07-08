package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

func logOperation(record LogRecord) {
	fmt.Printf("%v operation: %v X: %v Y: %v result: %v success: %v error: %v\n", record.DateTime, record.OpType, record.OperandX, record.OperandY, record.Result, record.Success, record.Error)
}

func main() {
	http.HandleFunc("/register", registerUserHandler)
	http.HandleFunc("/add", addHandler)
	http.HandleFunc("/sub", subHandler)
	http.HandleFunc("/mul", mulHandler)
	http.HandleFunc("/div", divHandler)
	http.HandleFunc("/pow", powHandler)
	http.HandleFunc("/root", rootHandler)
	fmt.Println("Server running on port 8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func decodeTwoOperands(r *http.Request) (float64, float64, error) {
	xStr := r.URL.Query().Get("x")
	yStr := r.URL.Query().Get("y")
	x, err := strconv.ParseFloat(xStr, 64)
	if err != nil {
		return 0, 0, errors.New("err_invalid_x")
	}
	y, err := strconv.ParseFloat(yStr, 64)
	if err != nil {
		return 0, 0, errors.New("err_invalid_y")
	}
	return x, y, nil
}
