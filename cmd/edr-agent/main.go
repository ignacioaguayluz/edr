// Command edr-agent is a minimal eBPF-based Endpoint Detection and Response
// agent for Linux. It must run as root, in the host pid namespace.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"edr/internal/agent"
	"edr/internal/detection"
	"edr/internal/response"
	"edr/internal/sensor/ebpf"
	"edr/internal/sink"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "edr-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	rulesDir := flag.String("rules", "rules", "directory containing *.yaml rule files")
	output := flag.String("output", "-", "JSON Lines output file ('-' for stdout)")
	dryRun := flag.Bool("dry-run", false, "report kill actions without killing")
	emitEvents := flag.Bool("emit-events", false, "write every telemetry event, not only alerts (very verbose)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	rules, err := detection.LoadDir(*rulesDir)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}

	var out io.Writer = os.Stdout
	if *output != "-" {
		f, err := os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open output: %w", err)
		}
		defer f.Close()
		out = f
	}

	sensor, err := ebpf.Open(log)
	if err != nil {
		return fmt.Errorf("start sensor (root and a BTF-enabled kernel are required): %w", err)
	}
	defer sensor.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := agent.New(detection.NewEngine(rules), response.New(*dryRun), sink.NewJSONL(out), agent.Options{
		EmitEvents:  *emitEvents,
		OnSinkError: func(err error) { log.Error("write output", "err", err) },
	})
	log.Info("agent started", "rules", len(rules), "dry_run", *dryRun, "emit_events", *emitEvents, "pid", os.Getpid())
	err = a.Run(ctx, sensor)
	log.Info("agent stopped")
	return err
}
