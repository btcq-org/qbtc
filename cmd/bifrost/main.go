package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/btcq-org/qbtc/bifrost/keystore"
	"github.com/btcq-org/qbtc/bifrost/p2p"
	btypes "github.com/btcq-org/qbtc/bifrost/types"
	qtypes "github.com/btcq-org/qbtc/x/qbtc/types"
	"google.golang.org/grpc"
)

func grpcClient() *grpc.ClientConn {
	conn, err := grpc.Dial("localhost:9090", grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	return conn
}

func run(ctx context.Context) error {

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	defer cancel()

	config := &btypes.P2PConfig{
		Port:       30006,
		ExternalIP: "127.0.0.1",
	}
	//  client to retrieve node peer addresses
	qClient := qtypes.NewQueryClient(grpcClient())

	kstore := keystore.NewMemoryKeyStore()
	privKey, err := keystore.GenerateKey(kstore)
	if err != nil {
		panic(err)
	}

	network := p2p.NewNetwork(config, qClient)
	err = network.Start(privKey)
	if err != nil {
		return err
	}

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
