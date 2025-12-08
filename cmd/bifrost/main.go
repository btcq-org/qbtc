package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/btcq-org/qbtc/bifrost"
	bifrostConfig "github.com/btcq-org/qbtc/bifrost/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	flag "github.com/spf13/pflag"
)

// THORNode define version / revision here , so THORNode could inject the version from CI pipeline if THORNode want to
var (
	version  string
	revision string
)

const (
	serverIdentity = "bifrost"
)

func printVersion() {
	fmt.Printf("%s v%s, rev %s\n", serverIdentity, version, revision)
}

func main() {
	showVersion := flag.Bool("version", false, "Shows version")
	logLevel := flag.StringP("log-level", "l", "info", "Log Level")
	pretty := flag.BoolP("pretty-log", "p", false, "Enables unstructured prettified logging. This is useful for local debugging")
	configPath := flag.StringP("config", "c", "", "Path to config file or directory containing config.json")
	flag.Parse()
	initLog(*logLevel, *pretty)
	if *showVersion {
		printVersion()
		return
	}

	var cfg *bifrostConfig.Config
	var err error
	if *configPath != "" {
		cfg, err = bifrostConfig.GetConfig(*configPath)
	} else {
		cfg, err = bifrostConfig.GetConfig()
	}

	if err != nil {
		log.Fatal().Err(err).Msg("failed to get bifrost config")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	service, err := bifrost.NewService(*cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create bifrost service")
	}
	if err := service.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to start bifrost service")
	}

	<-ctx.Done()
	log.Info().Msg("shutting down bifrost service...")
	service.Stop()
}

func initLog(level string, pretty bool) {
	l, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Warn().Msgf("%s is not a valid log-level, falling back to 'info'", level)
		l = zerolog.InfoLevel
	}
	var out io.Writer = os.Stdout
	if pretty {
		out = zerolog.ConsoleWriter{Out: os.Stdout}
	}
	zerolog.SetGlobalLevel(l)
	log.Logger = log.Output(out).With().Caller().Str("service", serverIdentity).Logger()

}
