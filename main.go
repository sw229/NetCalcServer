package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

// TODO:
// Add enable/disable admin handlers
// Use encoding/json/v2
// Add success/failure messages for all requests
// Add authentication and admin functionality
// Add ability to get database credentials from environment variables
// Add ability to specify custom port for database
// use toml or something like that for config file
// LogToFile setting is unnecessary, log file has to be used only if path to is it given
// Maybe split program into packages

func main() {
	settings := genSettings()
	lg, err := initLog(*settings.LogLevel, *settings.LogFilePath)
	if err != nil {
		log.Fatal(err)
	}
	db, err := initDB(settings)
	if err != nil {
		lg.logMsg(fmt.Sprintf("Failed to connect to database: %s", err), LogError)
		os.Exit(1)
	}

	http.HandleFunc("/ping", newPingHandler(db, lg))
	http.HandleFunc("/register", newRegisterHandler(db, lg))
	http.HandleFunc("/login", newLoginHandler(db, lg))
	http.HandleFunc("/delete", newDeleteHandler(db, lg))
	http.HandleFunc("/calculate", newCalcHandler(db, lg))
	http.HandleFunc("/admin/getusers", newGetUsersHandler(db, lg))
	http.HandleFunc("/admin/ban", newBanHandler(db, lg))
	http.HandleFunc("admin/adminstatus", newSetAdminHandler(db, lg))
	lg.logMsg(fmt.Sprintf("Server starting on port %s", *settings.ServerPort), LogInfo)
	err = http.ListenAndServe(":"+*settings.ServerPort, nil)
	if err != nil {
		lg.logMsg(fmt.Sprintf("Could not start server: %s", err), LogError)
		os.Exit(1)
	}
}
