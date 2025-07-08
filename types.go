package main

import "time"

type LogRecord struct {
	DateTime time.Time
	OpType   string
	OperandX float64
	OperandY float64
	Result   float64
	Success  bool
	Error    error
}

type User struct {
	Id             int
	Userame        string
	PasswdHash     string
	DateRegistered time.Time
	LastChanged    time.Time
	LastLogin      time.Time
	IsBanned       bool
	DateBanned     time.Time
	BanDuration    time.Duration
}
