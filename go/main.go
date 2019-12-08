package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

func main() {
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/cvproxy/")
	viper.AddConfigPath("$HOME/.cvproxy")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	rulesPath := viper.GetString("rulesPath")
	certKey := viper.GetString("certKey")
	certFile := viper.GetString("certFile")

	matcher := CreateMatcher()

	matcher.ParseRulesZipArchive(rulesPath)

	startGoProxyServer(certFile, certKey)

	var quit = false
	var line = ""

	reader := bufio.NewReader(os.Stdin)

	for !quit {
		line, _ = reader.ReadString('\n')
		if strings.TrimSpace(line) == "quit" {
			quit = true
		}
	}

	stopGoProxyServer()
}
