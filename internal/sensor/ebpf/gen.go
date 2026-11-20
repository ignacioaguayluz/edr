// Package ebpf is the kernel sensor adapter: it loads the eBPF probes,
// reads the ring buffer and translates raw records into telemetry.Event.
package ebpf

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -fms-extensions -Wno-microsoft-anon-tag" -target bpfel -type event bpf bpf/edr.bpf.c -- -I./bpf
