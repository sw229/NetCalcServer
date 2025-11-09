package logging

import (
	"log"
	"os"
	"strings"

	"github.com/sw229/netCalcServer/internal/types"
)

const (
	LogError = iota
	LogWarning
	LogInfo
	LogOperation
)

type Logging struct {
	level   int      //Logging level. 0 logs nothing, 1 logs errors, 2 logs errors+warinngs, 3 logs everything
	logfile *os.File // File where to store logs
}

func InitLog(logLevel int, logFilePath string) (Logging, error) {
	if logFilePath == "" {
		return Logging{logLevel, os.Stdout}, nil
	}
	if strings.HasPrefix(logFilePath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return Logging{}, types.ErrInvalidFile{Message: "Could not open log file. Unable to locate user home directory. Try using absolute path to log file"}
		}
		logFilePath = home + "/" + logFilePath[2:]
	}

	file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return Logging{}, err
	}
	return Logging{logLevel, file}, nil
}

func (lg Logging) LogMsg(msg string, msgType int) {
	if lg.level == 0 {
		return
	}
	if lg.level-msgType > 0 {
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
