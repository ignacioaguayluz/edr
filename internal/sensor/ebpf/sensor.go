//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"edr/internal/telemetry"
)

// Sensor owns the loaded eBPF objects and attached tracepoints.
type Sensor struct {
	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	// wall clock minus CLOCK_MONOTONIC, captured at start.
	clockOffset time.Duration
	log         *slog.Logger
}

// Open loads the probes into the kernel and attaches them. Requires root
// (CAP_BPF + CAP_PERFMON) and a kernel with BTF.
func Open(log *slog.Logger) (*Sensor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	if err := ensureTracefs(); err != nil {
		return nil, err
	}
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	if err := spec.Variables["agent_tgid"].Set(uint32(os.Getpid())); err != nil {
		return nil, fmt.Errorf("set agent_tgid: %w", err)
	}

	s := &Sensor{log: log}
	if err := spec.LoadAndAssign(&s.objs, nil); err != nil {
		return nil, fmt.Errorf("load objects: %w", err)
	}

	probes := []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"sched", "sched_process_exec", s.objs.HandleExec},
		{"sched", "sched_process_exit", s.objs.HandleExit},
		{"syscalls", "sys_enter_openat", s.objs.HandleOpenat},
		{"syscalls", "sys_enter_connect", s.objs.HandleConnect},
	}
	for _, p := range probes {
		l, err := link.Tracepoint(p.group, p.name, p.prog, nil)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", p.group, p.name, err)
		}
		s.links = append(s.links, l)
	}

	if s.reader, err = ringbuf.NewReader(s.objs.Events); err != nil {
		s.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		s.Close()
		return nil, fmt.Errorf("clock_gettime: %w", err)
	}
	s.clockOffset = time.Duration(time.Now().UnixNano() - ts.Nano())
	return s, nil
}

const tracefsPath = "/sys/kernel/tracing"

// ensureTracefs mounts tracefs when neither it nor debugfs is available
// (common in minimal containers); tracepoint attachment needs it.
func ensureTracefs() error {
	for _, p := range []string{tracefsPath + "/events", "/sys/kernel/debug/tracing/events"} {
		if _, err := os.Stat(p); err == nil {
			return nil
		}
	}
	if err := unix.Mount("tracefs", tracefsPath, "tracefs", 0, ""); err != nil {
		return fmt.Errorf("mount tracefs at %s: %w", tracefsPath, err)
	}
	return nil
}

func (s *Sensor) monoToWall(ns uint64) time.Time {
	return time.Unix(0, int64(ns)+int64(s.clockOffset))
}

// Run streams decoded events to out until ctx is cancelled. Malformed
// records are logged and skipped.
func (s *Sensor) Run(ctx context.Context, out chan<- telemetry.Event) error {
	stop := context.AfterFunc(ctx, func() { s.reader.Close() })
	defer stop()
	for {
		rec, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("ringbuf read: %w", err)
		}
		ev, err := decode(rec.RawSample, s.monoToWall)
		if err != nil {
			s.log.Warn("dropping malformed record", "err", err)
			continue
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}

// Close detaches probes and releases kernel resources. Safe to call twice.
func (s *Sensor) Close() error {
	var errs []error
	if s.reader != nil {
		errs = append(errs, s.reader.Close())
	}
	for _, l := range s.links {
		errs = append(errs, l.Close())
	}
	s.links = nil
	errs = append(errs, s.objs.Close())
	return errors.Join(errs...)
}
