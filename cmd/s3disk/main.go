package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/vibe-agi/s3disk/internal/cli"
)

var version = "development"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cli.ExecuteContextWithVersion(ctx, os.Args[1:], os.Stdout, os.Stderr, version); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "s3disk: %v\n", err)
		os.Exit(1)
	}
}
