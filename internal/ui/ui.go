package ui

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/sw229/netCalcServer/internal/types"
)

// Function processes command line arguments to set values to respective Settings fields
// Also returns the path to config file. If it is not given as an argument, default value is returned
// Values passed as flags override those from the configuration file
func processArgs() (types.Settings, string) {
	settings := types.Settings{}
	confPath := "~/.config/netcalcsrv.conf"

	args := os.Args[1:]
	for _, arg := range args {
		if arg == "--help" {
			printHelp()
			os.Exit(0)
		}
		if strings.HasPrefix(arg, "--config=") {
			confPath, _ = strings.CutPrefix(arg, "--config=")
		} else if strings.HasPrefix(arg, "--port=") {
			portStr, _ := strings.CutPrefix(arg, "--port=")
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 0 || port > 65535 {
				fmt.Fprintln(os.Stderr, "ERROR: --port value is invalid")
				os.Exit(2)
			}
			settings.ServerPort = &portStr
		} else if strings.HasPrefix(arg, "--db-name=") {
			dbName, _ := strings.CutPrefix(arg, "--db-name=")
			settings.DBName = &dbName
		} else if strings.HasPrefix(arg, "--db-username=") {
			dbUsername, _ := strings.CutPrefix(arg, "--db-username=")
			settings.DBUsername = &dbUsername
		} else if strings.HasPrefix(arg, "--db-password=") {
			dbPassword, _ := strings.CutPrefix(arg, "--db-password=")
			settings.DBPassword = &dbPassword
		} else if strings.HasPrefix(arg, "--log-file-path=") {
			logFilePath, _ := strings.CutPrefix(arg, "--log-file-path=")
			settings.LogFilePath = &logFilePath
			settings.LogToFile = Ptr(true)
		} else if strings.HasPrefix(arg, "--log-level=") {
			var err error
			logLevelStr, _ := strings.CutPrefix(arg, "--log-level=")
			logLevel, err := strconv.Atoi(logLevelStr)
			if err != nil || logLevel > 4 || logLevel < 0 {
				fmt.Fprintln(os.Stderr, "Error: --log-level value is invalid")
				os.Exit(2)
			}
			settings.LogLevel = &logLevel
		} else {
			fmt.Fprintf(os.Stderr, "ERROR: Invalid option %s\nUse --help for help\n", arg)
			os.Exit(2)
		}
	}
	return settings, confPath
}

// Function reads config file
// Path to config file passed as an argument
// Config file settings:
// port                        equivalent to Settings.ServerPort
// enable_log_file=true/false  equivalent to Settings.LogToFile
// log_file_path=FILE          equivalent to Settings.LogFilePath
// log_level=NUM               equivalent to Settings.LogLevel. Integer values 0-3 are allowed
// db_name=NAME                equivalent to Settings.DBName
// db_username=NAME            equivalent to Settings.DBUsername
// db_password=PASSWORD        equivalent to Settings.DBPassword
func ReadConfigFile(confPath string) (types.Settings, error) {
	if strings.HasPrefix(confPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return types.Settings{}, types.ErrInvalidFile{Message: "Could not open config file. Unable to locate user home directory. Try using absolute path to config file"}
		}
		confPath = home + "/" + confPath[2:]
	}
	settings := types.Settings{}
	file, err := os.Open(confPath)
	if err != nil {
		return types.Settings{}, err
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.Trim(line, " ")
		if strings.HasPrefix(strings.Trim(line, " "), "#") {
			continue
		}

		if strings.Contains(line, "=") {
			settingName := strings.ToLower(strings.Trim(strings.SplitN(line, "=", 2)[0], " "))
			settingValue := strings.Trim(strings.SplitN(line, "=", 2)[1], " ")

			switch settingName {
			case "port":
				port, err := strconv.Atoi(settingValue)
				if err != nil || port < 0 || port > 65535 {
					fmt.Fprintln(os.Stderr, "ERROR: Calue of port must be integer between 0 and 65535")
				}
				settings.ServerPort = &settingValue
			case "enable_log_file":
				if strings.ToLower(settingValue) == "true" {
					settings.LogToFile = Ptr(true)
				} else if strings.ToLower(settingValue) == "false" {
					settings.LogToFile = Ptr(false)
				} else {
					fmt.Fprintln(os.Stderr, "ERROR: Value of enable_log_file must be true or false")
				}
			case "log_file_path":
				settings.LogFilePath = &settingValue
			case "log_level":
				logLevel, err := strconv.Atoi(settingValue)
				if err != nil || logLevel > 4 || logLevel < 0 {
					fmt.Fprintln(os.Stderr, "ERROR: Value of log_level must be integer between 0 and 3")
				} else {
					settings.LogLevel = &logLevel
				}
			case "db_name":
				settings.DBName = &settingValue
			case "db_username":
				settings.DBUsername = &settingValue
			case "db_password":
				settings.DBPassword = &settingValue
			}
		}
	}
	if err = scanner.Err(); err != nil {
		return types.Settings{}, err
	}

	return settings, nil
}

// Function generates Settings struct from config file and flags.
// If at least one setting value is missing, program exits.
// Values given as flags override those from config file
// Function iterates through fields of argSettings, if any field is nil, it assigns a value
// of corresponding field from confSettings.
// If DBUsername or DBPassword are not given, function prompts user to type them.
// If only database username is given, user is prompted for password.
// If only password is given, user is prompted for both because this is stupid.
// If any other setting is not given, os.Exit(2) is called.
func GenSettings() types.Settings {
	argSettings, confPath := processArgs()
	confSettings, err := ReadConfigFile(confPath)

	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: error reading config file at %s\n%s\n", confPath, err)
	}

	argSettingsValue := reflect.ValueOf(&argSettings).Elem()
	confSettingsValue := reflect.ValueOf(confSettings)

	for i := range argSettingsValue.NumField() {
		field := argSettingsValue.Field(i)
		if field.Kind() == reflect.Ptr {
			if field.IsNil() {
				conffield := confSettingsValue.Field(i)
				if (!conffield.IsValid() || conffield.IsNil()) && !isPrompted(confSettingsValue.Type().Field(i)) {
					fmt.Fprintf(os.Stderr, "ERROR: value of field %s not given\n", argSettingsValue.Type().Field(i).Name)
					os.Exit(2)
				} else {
					argSettingsValue.Field(i).Set(confSettingsValue.Field(i))
				}
			}
		}
	}
	promptForDbCredentials(&argSettings.DBUsername, &argSettings.DBPassword)
	return argSettings
}

// Checks if a struct field is database username or password
func isPrompted(fieldValue reflect.StructField) bool {
	// fields of Settings struct that user can be prompted for
	dbUsernameFieldName := "DBUsername"
	dbPaswordFieldName := "DBPassword"

	fieldName := fieldValue.Name
	if fieldName == dbUsernameFieldName || fieldName == dbPaswordFieldName {
		return true
	}
	return false
}

// Function prompts user for database login credentials.
// If database username is given, user is only prompted for password.
// If only password is given, user is prompted for both username and password
// Double pointer is used because Settings stores all values as pointers
// So I am passing a pointer to pointer to modify the underlying pointer
func promptForDbCredentials(dbUsername, dbPassword **string) {
	var (
		dbUsernameLocal string
		dbPasswordLocal string
	)

	if *dbUsername == nil {
		fmt.Println("Username for database connection:")
		fmt.Scanln(&dbUsernameLocal)
		*dbUsername = &dbUsernameLocal
		fmt.Printf("Password for %s:\n", dbUsernameLocal)
		fmt.Scanln(&dbPasswordLocal)
		*dbPassword = &dbPasswordLocal
	}
	if *dbPassword == nil {
		fmt.Printf("Password for %s:\n", **dbUsername)
		fmt.Scanln(&dbPasswordLocal)
		*dbPassword = &dbPasswordLocal
	}
}

func printHelp() {
	helpMsg := `Usage: netcalcsrv [OPTION]
	--config=FILE          set config file. Default path is ~/.config/netcalcsrv.conf
	--port=NUM             set port for the server to listen on. Integer values between 0 and 65535 are acepted
	--db-name=NAME         set database name. Only mysql/mariadb supported
	--db-username=USEENAME set username to connect to database
	--db-password=PASSWORD set password to connect to database
	--log-file-path=FILE   set path to log file. If no path is given, logs are shown in stdout
	--log-level=NUM        set logging level. Level 0 logs nothing, level 1 only logs errors,
	                       level 2 logs user register/login/logout, level 3 logs all calculations`
	fmt.Println(helpMsg)
}

func Ptr[T any](v T) *T {
	return &v
}
