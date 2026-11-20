package telemetry

import "testing"

func TestFieldResolvesEveryKnownField(t *testing.T) {
	ev := Event{
		Kind:    KindNetConnect,
		Process: Process{PID: 10, PPID: 1, UID: 0, Comm: "nc", Exe: "/usr/bin/nc", Args: []string{"nc", "-e"}, ParentComm: "bash"},
		File:    &File{Path: "/etc/shadow"},
		Network: &Network{Family: "ipv4", DstIP: "10.0.0.1", DstPort: 4444},
	}
	want := map[string]string{
		"kind": "net_connect", "process.pid": "10", "process.ppid": "1", "process.uid": "0",
		"process.comm": "nc", "process.exe": "/usr/bin/nc", "process.args": "nc -e",
		"process.parent_comm": "bash", "file.path": "/etc/shadow", "network.family": "ipv4",
		"network.dst_ip": "10.0.0.1", "network.dst_port": "4444",
	}
	if len(want) != len(KnownFields) {
		t.Fatalf("test covers %d fields, KnownFields has %d", len(want), len(KnownFields))
	}
	for name, exp := range want {
		got, ok := ev.Field(name)
		if !ok || got != exp {
			t.Errorf("Field(%q) = %q,%v; want %q,true", name, got, ok, exp)
		}
	}
}

func TestFieldAbsentForMissingSections(t *testing.T) {
	ev := Event{Kind: KindProcessExec}
	for _, name := range []string{"file.path", "network.dst_ip", "network.dst_port", "process.exe", "process.args", "process.parent_comm", "unknown"} {
		if _, ok := ev.Field(name); ok {
			t.Errorf("Field(%q) reported present on empty event", name)
		}
	}
}
