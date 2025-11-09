package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/sw229/netCalcServer/internal/database"
	"github.com/sw229/netCalcServer/internal/handlers"
	"github.com/sw229/netCalcServer/internal/logging"
	"github.com/sw229/netCalcServer/internal/ui"
)

// TODO:
// BUG: server creates log file on startup even when enable_log_file=false
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
	settings := ui.GenSettings()
	lg, err := logging.InitLog(*settings.LogLevel, *settings.LogFilePath)
	if err != nil {
		log.Fatal(err)
	}
	db, err := database.InitDB(settings)
	if err != nil {
		lg.LogMsg(fmt.Sprintf("Failed to connect to database: %s", err), logging.LogError)
		os.Exit(1)
	}

	http.HandleFunc("/ping", handlers.NewPingHandler(db, lg))
	http.HandleFunc("/register", handlers.NewRegisterHandler(db, lg))
	http.HandleFunc("/login", handlers.NewLoginHandler(db, lg))
	http.HandleFunc("/delete", handlers.NewDeleteHandler(db, lg))
	http.HandleFunc("/calculate", handlers.NewCalcHandler(db, lg))
	http.HandleFunc("/admin/getusers", handlers.NewGetUsersHandler(db, lg))
	http.HandleFunc("/admin/ban", handlers.NewBanHandler(db, lg))
	http.HandleFunc("admin/adminstatus", handlers.NewSetAdminHandler(db, lg))
	lg.LogMsg(fmt.Sprintf("Server starting on port %s", *settings.ServerPort), logging.LogInfo)
	err = http.ListenAndServe(":"+*settings.ServerPort, nil)
	if err != nil {
		lg.LogMsg(fmt.Sprintf("Could not start server: %s", err), logging.LogError)
		os.Exit(1)
	}
}
