package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

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

	certKey := viper.GetString("certKey")
	certFile := viper.GetString("certFile")
	port := viper.GetInt("port")
	icapServerReqUrl := viper.GetString("icapServerReqUrl")
	icapServerRespUrl := viper.GetString("icapServerRespUrl")

	startGoProxyServer(certFile, certKey, icapServerReqUrl, icapServerRespUrl, int16(port))

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs)
	for sig := range sigs {
		log.Printf("RECEIVED SIGNAL: %s", sig)
		switch sig {
		case syscall.SIGURG:
			log.Printf("ignoring sigurg")
		default:
			stopGoProxyServer()
			os.Exit(1)
		}
	}
}
