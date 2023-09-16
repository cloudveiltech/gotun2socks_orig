package main

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

func main() {
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/goremote/")
	viper.AddConfigPath("$HOME/.goremote")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	certKey := viper.GetString("certKey")
	certFile := viper.GetString("certFile")
	proxyPort := viper.GetInt("proxyPort")
	tunnelPort := viper.GetInt("tunnelPort")
	icapServerReqUrl := viper.GetString("icapServerReqUrl")
	icapServerRespUrl := viper.GetString("icapServerRespUrl")
	forwardProxyAddress := viper.GetString("forwardProxyAddress")

	startGoProxyServer(certFile, certKey, icapServerReqUrl, icapServerRespUrl, uint16(proxyPort), uint16(tunnelPort), forwardProxyAddress)

	for {
		time.Sleep(time.Second)
	}
}
