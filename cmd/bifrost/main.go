package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"

	bifrostConfig "github.com/btcq-org/qbtc/bifrost/config"
	"github.com/btcq-org/qbtc/bifrost/keystore"
	"github.com/btcq-org/qbtc/bifrost/p2p"
	"github.com/btcq-org/qbtc/bifrost/qclient"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cast"
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

func run(ctx context.Context, cfg *bifrostConfig.Config) error {
	// handle signals
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	_, p, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return err
	}
	config := &bifrostConfig.P2PConfig{
		Port:       cast.ToInt(p),
		ExternalIP: cfg.ExternalIP,
	}
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	_ = logger
	//  client to retrieve node peer addresses
	qClient, err := qclient.New(fmt.Sprintf("localhost:%d", 9090), true)
	if err != nil {
		return fmt.Errorf("fail to created client to qbtc node,err: %w", err)
	}

	defer qClient.Close()
	kstore, err := keystore.NewFileKeyStore(cfg.RootPath)
	if err != nil {
		return fmt.Errorf("failed to create file key store,err: %w", err)
	}
	privKey, err := keystore.GetOrCreateKey(kstore, cfg.KeyName)
	if err != nil {
		return fmt.Errorf("failed to get or create p2p key, err: %w", err)
	}

	network, err := p2p.NewNetwork(config, qClient)
	if err != nil {
		return fmt.Errorf("failed to create p2p network, err: %w", err)
	}
	err = network.Start(ctx, privKey)
	if err != nil {
		return fmt.Errorf("failed to start p2p network, err: %w", err)
	}

	defer func() {
		if err := network.Stop(); err != nil {
			slog.Error("failed to stop network", "err", err)
		}
	}()

	host := network.GetHost()
	logger.Info().Msgf("starting bifrost p2p network, id: %s, listen_addr: %s", host.ID(), network.GetListenAddr())
	<-ctx.Done()
	return nil
}

func main() {
	showVersion := flag.Bool("version", false, "Shows version")
	logLevel := flag.StringP("log-level", "l", "info", "Log Level")
	pretty := flag.BoolP("pretty-log", "p", false, "Enables unstructured prettified logging. This is useful for local debugging")
	flag.Parse()
	initLog(*logLevel, *pretty)
	if *showVersion {
		printVersion()
		return
	}
	cfg, err := bifrostConfig.GetConfig()
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	if err := run(ctx, cfg); err != nil {
		panic(err)
	}
}

func initLog(level string, pretty bool) {
	l, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Warn().Msgf("%s is not a valid log-level, falling back to 'info'", level)
	}
	var out io.Writer = os.Stdout
	if pretty {
		out = zerolog.ConsoleWriter{Out: os.Stdout}
	}
	zerolog.SetGlobalLevel(l)
	log.Logger = log.Output(out).With().Caller().Str("service", serverIdentity).Logger()

}
