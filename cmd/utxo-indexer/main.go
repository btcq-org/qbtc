package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/btcq-org/qbtc/bitcoin"
)

func main() {
	cfg, err := bitcoin.GetConfig()
	if err != nil {
		panic(err)
	}
	indexer, err := bitcoin.NewIndexer(*cfg)
	if err != nil {
		panic(err)
	}
	if err := indexer.Start(); err != nil {
		panic(err)
	}
	// wait for termination signal (Ctrl+C / SIGINT or SIGTERM)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("received signal %v, shutting down\n", s)
	indexer.Stop()
}
