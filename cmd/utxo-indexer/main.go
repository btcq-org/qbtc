package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/btcq-org/qbtc/bitcoin"
)

var (
	exportUTXO     = flag.Bool("export-utxo", false, "export utxo from db and exit")
	exportUTXOFile = flag.String("export-utxo-file", "", "path to write exported utxos (default stdout)")
)

func main() {
	flag.Parse()
	cfg, err := bitcoin.GetConfig()
	if err != nil {
		panic(err)
	}
	indexer, err := bitcoin.NewIndexer(*cfg)
	if err != nil {
		panic(err)
	}
	// if export flag is set, export and exit
	if *exportUTXO {
		if err := indexer.ExportUTXO(*exportUTXOFile); err != nil {
			panic(err)
		}
		return
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
