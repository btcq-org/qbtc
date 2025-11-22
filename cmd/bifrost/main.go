package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/btcq-org/qbtc/bifrost/keystore"
	"github.com/btcq-org/qbtc/bifrost/p2p"
	"github.com/btcq-org/qbtc/bifrost/qclient"
	btypes "github.com/btcq-org/qbtc/bifrost/types"
	"github.com/spf13/cast"
	flag "github.com/spf13/pflag"
)

func run(ctx context.Context) error {
	listenAddr := flag.String("listen-addr", "0.0.0.0:30006", "Listen address of the node")
	externalIP := flag.String("external-ip", "", "External IP of the node")
	rootPath := flag.String("root-path", ".bifrost", "Root path of the keystore")
	keyName := flag.String("key-name", "bifrost-p2p-key", "Name of the key to use for the p2p network")
	flag.Parse()

	// handle signals
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	_, p, err := net.SplitHostPort(*listenAddr)
	if err != nil {
		return err
	}
	config := &btypes.P2PConfig{
		Port:       cast.ToInt(p),
		ExternalIP: *externalIP,
	}
	//  client to retrieve node peer addresses
	qClient, err := qclient.New(fmt.Sprintf("localhost:%d", 9090), true)
	if err != nil {
		return err
	}

	defer qClient.Close()
	kstore, err := keystore.NewFileKeyStore(*rootPath)
	if err != nil {
		return err
	}
	privKey, err := keystore.GetOrCreateKey(kstore, *keyName)
	if err != nil {
		return err
	}

	network, err := p2p.NewNetwork(config, qClient)
	if err != nil {
		return err
	}
	err = network.Start(ctx, privKey)
	if err != nil {
		return err
	}

	defer func() {
		if err := network.Stop(); err != nil {
			slog.Error("failed to stop network", "err", err)
		}
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	host := network.GetHost()
	slog.Info("starting bifrost p2p network", "id", host.ID(), "listen_addr", network.GetListenAddr())

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			host := network.GetHost()
			slog.Info("bifrost p2p running...", "id", host.ID(), "listen_addr", network.GetListenAddr())
		}
	}

}
func main() {
	ctx := context.Background()
	err := run(ctx)
	if err != nil {
		fmt.Printf("error %s\n", err.Error())
		os.Exit(1)
	}
}
