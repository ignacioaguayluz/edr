//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"edr/internal/telemetry"
)

func encode(t *testing.T, r bpfEvent) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, r); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func fixedWall(ns uint64) time.Time { return time.Unix(0, int64(ns)) }

func base(kind uint32) bpfEvent {
	r := bpfEvent{TsNs: 5, StartNs: 4_200_000_000, Kind: kind, Pid: 10, Ppid: 1, Uid: 1000}
	copy(r.Comm[:], "bash\x00garbage")
	return r
}

func TestDecodeExec(t *testing.T) {
	r := base(evExec)
	copy(r.Path[:], "/usr/bin/nc\x00")
	args := "nc\x00-l\x004444\x00"
	copy(r.Args[:], args+"stale-bytes")
	r.ArgsLen = uint32(len(args))
	ev, err := decode(encode(t, r), fixedWall)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != telemetry.KindProcessExec || ev.Process.Exe != "/usr/bin/nc" || ev.Process.Comm != "bash" ||
		ev.Process.PID != 10 || ev.Process.PPID != 1 || ev.Process.UID != 1000 || !ev.Time.Equal(time.Unix(0, 5)) ||
		ev.Process.StartBootNS != 4_200_000_000 {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if got := ev.Process.Args; len(got) != 3 || got[0] != "nc" || got[2] != "4444" {
		t.Fatalf("args = %q", got)
	}
}

func TestDecodeExit(t *testing.T) {
	for raw, want := range map[int32]int{0: 0, 3 << 8: 3, 9: 137} {
		r := base(evExit)
		r.ExitCode = raw
		ev, err := decode(encode(t, r), fixedWall)
		if err != nil {
			t.Fatal(err)
		}
		if ev.Kind != telemetry.KindProcessExit || ev.Process.ExitCode == nil || *ev.Process.ExitCode != want {
			t.Errorf("raw %d: got %+v", raw, ev.Process.ExitCode)
		}
	}
}

func TestDecodeOpen(t *testing.T) {
	r := base(evOpen)
	copy(r.Path[:], "/etc/shadow\x00")
	r.Flags = 2
	ev, err := decode(encode(t, r), fixedWall)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != telemetry.KindFileOpen || ev.File == nil || ev.File.Path != "/etc/shadow" || ev.File.Flags != 2 {
		t.Fatalf("unexpected: %+v", ev)
	}
}

func TestDecodeConnect(t *testing.T) {
	r := base(evConnect)
	r.Family, r.Dport = afInet, 4444
	copy(r.Daddr[:], []byte{10, 0, 0, 7})
	ev, err := decode(encode(t, r), fixedWall)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Network == nil || ev.Network.Family != "ipv4" || ev.Network.DstIP != "10.0.0.7" || ev.Network.DstPort != 4444 {
		t.Fatalf("unexpected: %+v", ev.Network)
	}

	r.Family = afInet6
	r.Daddr = [16]byte{15: 1}
	ev, err = decode(encode(t, r), fixedWall)
	if err != nil || ev.Network.Family != "ipv6" || ev.Network.DstIP != "::1" {
		t.Fatalf("ipv6: %+v %v", ev.Network, err)
	}
}

func TestDecodeRejectsUnknownKindAndShortRecords(t *testing.T) {
	if _, err := decode(encode(t, base(99)), fixedWall); err == nil {
		t.Error("unknown kind accepted")
	}
	if _, err := decode([]byte{1, 2, 3}, fixedWall); err == nil {
		t.Error("short record accepted")
	}
}
