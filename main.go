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
	port := viper.GetInt("port")
	icapServerReqUrl := viper.GetString("icapServerReqUrl")
	icapServerRespUrl := viper.GetString("icapServerRespUrl")

	startGoProxyServer(certFile, certKey, icapServerReqUrl, icapServerRespUrl, uint16(port))

	for {
		time.Sleep(time.Second)
	}
}
