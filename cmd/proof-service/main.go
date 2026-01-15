package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"

	proofservice "github.com/btcq-org/qbtc/proof-service"
	proofConfig "github.com/btcq-org/qbtc/proof-service/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	flag "github.com/spf13/pflag"
)

var (
	version  string
	revision string
)

const serverIdentity = "proof-service"

func printVersion() {
	fmt.Printf("%s v%s, rev %s\n", serverIdentity, version, revision)
}

func main() {
	showVersion := flag.Bool("version", false, "Shows version")
	logLevel := flag.StringP("log-level", "l", "info", "Log Level")
	pretty := flag.BoolP("pretty-log", "p", false, "Enables prettified logging for local debugging")
	configPath := flag.StringP("config", "c", "", "Path to config file or directory containing config.json")
	flag.Parse()

	initLog(*logLevel, *pretty)

	if *showVersion {
		printVersion()
		return
	}

	// Load config
	var cfg *proofConfig.Config
	var err error
	if *configPath != "" {
		cfg, err = proofConfig.GetConfig(*configPath)
	} else {
		cfg, err = proofConfig.GetConfig()
	}
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	// Setup context with signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Create and start service
	service, err := proofservice.NewService(*cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create proof-service")
	}

	if err := service.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to start proof-service")
	}

	// Wait for shutdown signal
	<-ctx.Done()
	log.Info().Msg("received shutdown signal")
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
