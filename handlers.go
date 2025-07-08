package main

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"
)

func registerUserHandler(w http.ResponseWriter, r *http.Request) {

}

func addHandler(w http.ResponseWriter, r *http.Request) {
	record := LogRecord{
		DateTime: time.Now(),
		OpType:   "add",
	}
	x, y, err := decodeTwoOperands(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		record.Error = err
		logOperation(record)
		return
	}
	result := x + y
	fmt.Fprint(w, result)
	record.OperandX = x
	record.OperandY = y
	record.Result = result
	record.Success = true
	logOperation(record)
}

func subHandler(w http.ResponseWriter, r *http.Request) {
	record := LogRecord{
		DateTime: time.Now(),
		OpType:   "sub",
	}
	x, y, err := decodeTwoOperands(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		record.Error = err
		logOperation(record)
		return
	}
	result := x - y
	fmt.Fprint(w, result)
	record.OperandX = x
	record.OperandY = y
	record.Result = result
	record.Success = true
	logOperation(record)
}

func mulHandler(w http.ResponseWriter, r *http.Request) {
	record := LogRecord{
		DateTime: time.Now(),
		OpType:   "mul",
	}
	x, y, err := decodeTwoOperands(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		record.Error = err
		logOperation(record)
		return
	}
	result := x * y
	fmt.Fprint(w, result)
	record.OperandX = x
	record.OperandY = y
	record.Result = result
	record.Success = true
	logOperation(record)
}

func divHandler(w http.ResponseWriter, r *http.Request) {
	record := LogRecord{
		DateTime: time.Now(),
		OpType:   "div",
	}
	x, y, err := decodeTwoOperands(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		record.Error = err
		logOperation(record)
		return
	}
	if y == 0 {
		http.Error(w, "err_zero_div", http.StatusBadRequest)
		record.Error = errors.New("err_zero_div")
		logOperation(record)
		return
	}
	result := x / y
	fmt.Fprint(w, result)
	record.OperandX = x
	record.OperandY = y
	record.Result = result
	record.Success = true
	logOperation(record)
}

func powHandler(w http.ResponseWriter, r *http.Request) {
	record := LogRecord{
		DateTime: time.Now(),
		OpType:   "pow",
	}
	x, y, err := decodeTwoOperands(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		record.Error = err
		logOperation(record)
		return
	}
	result := math.Pow(x, y)
	fmt.Fprint(w, result)
	record.OperandX = x
	record.OperandY = y
	record.Result = result
	record.Success = true
	logOperation(record)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	record := LogRecord{
		DateTime: time.Now(),
		OpType:   "root",
	}
	x, y, err := decodeTwoOperands(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		record.Error = err
		logOperation(record)
		return
	}
	if y == 0 {
		http.Error(w, "err_invalid_root", http.StatusBadRequest)
		record.Error = errors.New("err_invalid_root")
		logOperation(record)
		return
	}
	result := math.Pow(x, 1/y)
	fmt.Fprint(w, result)
	record.OperandX = x
	record.OperandY = y
	record.Result = result
	record.Success = true
	logOperation(record)
}
