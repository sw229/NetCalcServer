package main

import (
	"log"
	"os"
	"strings"
)

const (
	LogError = iota
	LogWarning
	LogInfo
	LogOperation
)

type Logging struct {
	Level   int
	Logfile *os.File
}

func initLog(logLevel int, logFilePath string) (Logging, error) {
	if logFilePath == "" {
		return Logging{logLevel, os.Stdout}, nil
	}
	if strings.HasPrefix(logFilePath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return Logging{}, ErrInvalidFile{"Could not open log file. Unable to locate user home directory. Try using absolute path to log file"}
		}
		logFilePath = home + "/" + logFilePath[2:]
	}

	file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return Logging{}, err
	}
	return Logging{logLevel, file}, nil
}

func (lg Logging) logMsg(msg string, msgType int) {
	if lg.Level == 0 {
		return
	}
	if lg.Level-msgType > 0 {
		msgTypeString := ""
		switch msgType {
		case 0:
			msgTypeString = "ERROR"
		case 1:
			msgTypeString = "WARNING"
		case 2:
			msgTypeString = "INFO"
		}
		log.Printf("%s: %s", msgTypeString, msg)
	}
}
