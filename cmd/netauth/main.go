package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/spf13/viper"

	"github.com/netauth/netauth/internal/ctl"

	_ "github.com/netauth/netauth/pkg/netauth/cache/fs"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"

	appLogger hclog.Logger
)

func main() {
	// This runs here so we can reset the defaults that are set
	// during various init() methods.
	viper.SetDefault("token.cache", "fs")

	level, set := os.LookupEnv("NETAUTH_LOGLEVEL")
	if !set {
		appLogger = hclog.NewNullLogger()
	} else {
		appLogger = hclog.New(&hclog.LoggerOptions{
			Name:  "netauth",
			Level: hclog.LevelFromString(level),
		})
	}
	hclog.SetDefault(appLogger)
	appLogger.Debug("Build information as follows", "version", version, "commit", commit, "builddate", date)

	ctl.Execute()
}
