//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"edr/internal/telemetry"
)

// Mirrors enum event_kind in bpf/edr.bpf.c.
const (
	evExec    = 1
	evExit    = 2
	evOpen    = 3
	evConnect = 4

	afInet  = 2
	afInet6 = 10
)

// decode converts one ring buffer record into a telemetry event.
// monoToWall converts the kernel CLOCK_MONOTONIC timestamp to wall time.
func decode(raw []byte, monoToWall func(uint64) time.Time) (telemetry.Event, error) {
	var r bpfEvent
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &r); err != nil {
		return telemetry.Event{}, fmt.Errorf("decode event: %w", err)
	}
	ev := telemetry.Event{
		Time: monoToWall(r.TsNs),
		Process: telemetry.Process{
			PID: r.Pid, PPID: r.Ppid, UID: r.Uid, Comm: cString(r.Comm[:]),
		},
	}
	switch r.Kind {
	case evExec:
		ev.Kind = telemetry.KindProcessExec
		ev.Process.Exe = cString(r.Path[:])
		ev.Process.Args = splitArgs(r.Args[:min(int(r.ArgsLen), len(r.Args))])
	case evExit:
		ev.Kind = telemetry.KindProcessExit
		code := exitStatus(r.ExitCode)
		ev.Process.ExitCode = &code
	case evOpen:
		ev.Kind = telemetry.KindFileOpen
		ev.File = &telemetry.File{Path: cString(r.Path[:]), Flags: r.Flags}
	case evConnect:
		ev.Kind = telemetry.KindNetConnect
		n := &telemetry.Network{DstPort: r.Dport}
		switch r.Family {
		case afInet:
			n.Family = "ipv4"
			n.DstIP = netip.AddrFrom4([4]byte(r.Daddr[:4])).String()
		case afInet6:
			n.Family = "ipv6"
			n.DstIP = netip.AddrFrom16(r.Daddr).String()
		default:
			return telemetry.Event{}, fmt.Errorf("unexpected address family %d", r.Family)
		}
		ev.Network = n
	default:
		return telemetry.Event{}, fmt.Errorf("unknown event kind %d", r.Kind)
	}
	return ev, nil
}

// exitStatus maps a raw wait status to a shell-style exit code
// (128+signal when the process was killed by a signal).
func exitStatus(raw int32) int {
	if sig := raw & 0x7f; sig != 0 {
		return 128 + int(sig)
	}
	return int(raw>>8) & 0xff
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func splitArgs(b []byte) []string {
	b = bytes.TrimRight(b, "\x00")
	if len(b) == 0 {
		return nil
	}
	parts := bytes.Split(b, []byte{0})
	args := make([]string, len(parts))
	for i, p := range parts {
		args[i] = string(p)
	}
	return args
}
