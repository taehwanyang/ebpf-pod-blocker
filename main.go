//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type ip_pair_key -type rl_config -type rl_state count_conn_and_drop count_conn_and_drop.c -- -O2 -g -I/usr/include/aarch64-linux-gnu

package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received interrupt signal, shutting down...")
		cancel()
	}()

	if err := CreateTCHookAndShowDropLog(ctx); err != nil &&
		!errors.Is(err, context.Canceled) {
		log.Fatalf("runtime error: %v", err)
	}
}
