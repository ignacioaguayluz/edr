// Package agent wires telemetry sources to detection, response and output.
// It depends only on ports (interfaces); adapters are injected by cmd/.
package agent

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"edr/internal/detection"
	"edr/internal/telemetry"
)

// Source produces telemetry until ctx is cancelled or it is exhausted.
type Source interface {
	Run(ctx context.Context, out chan<- telemetry.Event) error
}

// Detector turns events into alerts.
type Detector interface {
	Evaluate(telemetry.Event) []detection.Alert
}

// Responder executes alert actions; nil means no action was taken.
type Responder interface {
	Respond(detection.Alert) *detection.ResponseOutcome
}

// Sink persists output records ("event" or "alert").
type Sink interface {
	Write(recordType string, data any) error
}

// Options tunes agent behavior.
type Options struct {
	EmitEvents  bool // write every event, not only alerts (very verbose)
	MaxTracked  int  // process table capacity; default 65536
	OnSinkError func(error)
}

// Agent enriches events with process context, runs detection and response.
type Agent struct {
	detector  Detector
	responder Responder
	sink      Sink
	opts      Options
	procs     *processTable
	procExe   func(pid uint32) string
	procComm  func(pid uint32) string
}

// New builds an agent that resolves missing process context from /proc.
func New(d Detector, r Responder, s Sink, opts Options) *Agent {
	if opts.MaxTracked <= 0 {
		opts.MaxTracked = 65536
	}
	if opts.OnSinkError == nil {
		opts.OnSinkError = func(error) {}
	}
	return &Agent{
		detector: d, responder: r, sink: s, opts: opts,
		procs:   newProcessTable(opts.MaxTracked),
		procExe: readProcExe, procComm: readProcComm,
	}
}

// Run consumes src until it stops or ctx is cancelled. Events are handled
// sequentially, so the process table needs no locking.
func (a *Agent) Run(ctx context.Context, src Source) error {
	events := make(chan telemetry.Event, 8192)
	errc := make(chan error, 1)
	go func() {
		errc <- src.Run(ctx, events)
		close(events)
	}()
	for ev := range events {
		a.Handle(ev)
	}
	return <-errc
}

// Handle processes a single event.
func (a *Agent) Handle(ev telemetry.Event) {
	a.enrich(&ev)
	if a.opts.EmitEvents {
		a.write("event", ev)
	}
	for _, alert := range a.detector.Evaluate(ev) {
		alert.Response = a.responder.Respond(alert)
		a.write("alert", alert)
	}
	if ev.Kind == telemetry.KindProcessExit {
		a.procs.remove(ev.Process.PID)
	}
}

func (a *Agent) enrich(ev *telemetry.Event) {
	p := &ev.Process
	if ev.Kind == telemetry.KindProcessExec {
		if !filepath.IsAbs(p.Exe) {
			if exe := a.procExe(p.PID); exe != "" {
				p.Exe = exe
			}
		}
		if parent, ok := a.procs.get(p.PPID); ok {
			p.ParentComm = parent.Comm
		} else {
			p.ParentComm = a.procComm(p.PPID)
		}
		a.procs.put(*p)
		return
	}
	// Other events carry only kernel basics; inherit exec-time context.
	if known, ok := a.procs.get(p.PID); ok {
		p.Exe, p.Args, p.ParentComm = known.Exe, known.Args, known.ParentComm
	}
}

func (a *Agent) write(kind string, data any) {
	if err := a.sink.Write(kind, data); err != nil {
		a.opts.OnSinkError(err)
	}
}

// processTable remembers exec-time context for live processes.
type processTable struct {
	max  int
	byID map[uint32]telemetry.Process
}

func newProcessTable(max int) *processTable {
	return &processTable{max: max, byID: make(map[uint32]telemetry.Process)}
}

func (t *processTable) get(pid uint32) (telemetry.Process, bool) {
	p, ok := t.byID[pid]
	return p, ok
}

// put stores p; when full, new pids are dropped (lost exit events must not
// grow memory without bound) but existing entries are still updated.
func (t *processTable) put(p telemetry.Process) {
	if _, exists := t.byID[p.PID]; !exists && len(t.byID) >= t.max {
		return
	}
	t.byID[p.PID] = p
}

func (t *processTable) remove(pid uint32) { delete(t.byID, pid) }

func readProcExe(pid uint32) string {
	exe, _ := os.Readlink("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/exe")
	return exe
}

func readProcComm(pid uint32) string {
	b, _ := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/comm")
	return strings.TrimSpace(string(b))
}
