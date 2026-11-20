# edr

A minimal Endpoint Detection and Response agent for Linux. eBPF probes collect process, file and network telemetry in the kernel; a YAML rule engine detects suspicious behavior; a responder can kill the offending process.

## How it works

```
kernel (eBPF CO-RE)                    user space (Go)
┌──────────────────────────┐   ring   ┌────────┐  ┌─────────┐  ┌───────────┐  ┌──────────┐  ┌───────┐
│ sched_process_exec/exit  │  buffer  │ sensor │→ │ enrich  │→ │ detection │→ │ response │→ │ JSONL │
│ sys_enter_openat/connect │ ───────→ │ decode │  │ (procs) │  │ (rules)   │  │ (kill)   │  │ sink  │
└──────────────────────────┘          └────────┘  └─────────┘  └───────────┘  └──────────┘  └───────┘
```

| Package | Role |
|---|---|
| `internal/telemetry` | Kernel-independent event model and rule field names |
| `internal/sensor/ebpf` | eBPF program (`bpf/edr.bpf.c`) and Go loader/decoder |
| `internal/agent` | Pipeline and process-context enrichment (exe, args, parent) |
| `internal/detection` | Rule model, YAML loader and engine |
| `internal/response` | pidfd-based kill, dry-run, protected PIDs |
| `internal/sink` | JSON Lines output |

`agent`, `detection` and `response` depend only on interfaces and are unit-tested without a kernel.

## Requirements

Docker. Everything builds and runs in containers, so the host needs no Go or clang. The kernel (the Docker Desktop VM or a Linux host) must be 5.8 or newer (ring buffer, `pidfd_open`, `start_boottime`) and provide BTF (`/sys/kernel/btf/vmlinux`).

## Usage

```sh
make test     # unit tests
make e2e      # real kernel: sensor tests + full agent attack simulation
make run      # run the agent with ./rules, alerts to stdout
make run ARGS="--dry-run --emit-events"
make image-runtime && docker run --rm --privileged --pid=host edr-agent
```

Kills target a process instance, not a bare PID. Every event carries the process start time from the kernel. The responder opens a pidfd, checks that `/proc/<pid>/stat` reports the same start time, and only then sends `SIGKILL` through the pidfd. The check has the resolution of `/proc` start times (10 ms): a PID that wraps around and is reused within the same tick, before the pidfd is opened, would not be detected. A reused PID is reported as `"status":"gone","error":"pid reused by another process"` and is never signalled. An alert without a start time is not killed (`skipped`).

Flags: `--rules DIR`, `--output FILE|-`, `--dry-run`, `--emit-events` (every event, not only alerts).

The agent needs root and the host PID namespace (`--privileged --pid=host` in Docker). The kernel reports host PIDs, so a namespaced agent would kill the wrong process.

## Rules

Every `*.yaml`/`*.yml` file in the rules directory is loaded, including every `---`-separated document. A missing directory, a directory with no rules, unknown keys, unknown fields, and duplicate IDs stop the agent at startup.

```yaml
rules:
  - id: EDR-002
    title: Shell spawned by a web server
    severity: high            # low | medium | high | critical
    kind: process_exec        # process_exec | process_exit | file_open | net_connect (omit = any)
    action: kill              # alert (default) | kill
    match:                    # all conditions must match
      - field: process.comm
        in: [sh, bash, dash, zsh]
      - field: process.parent_comm
        in: [nginx, apache2, httpd, php-fpm]
```

Each condition has exactly one of these operators: `equals`, `contains`, `startswith`, `endswith`, `in`. Fields: `kind`, `process.{pid,ppid,uid,comm,exe,args,parent_comm}`, `file.path`, `network.{family,dst_ip,dst_port}`.

Example alert:

```json
{"type":"alert","data":{"rule_id":"EDR-001","title":"Known cryptocurrency miner executed","severity":"critical","action":"kill","event":{"kind":"process_exec","process":{"pid":7538,"comm":"xmrig","exe":"/tmp/.../xmrig", "...":"..."}},"response":{"action":"kill","status":"killed"}}}
```

## Known limitations

- If user space falls behind (or a local user floods `openat`), the 16 MiB ring buffer fills and events are dropped. Drops are counted in the kernel and logged as `telemetry events dropped` every 10s, but they are not recovered.
- `openat` paths are read at syscall entry: they can be relative, and are empty if the user page is not resident. `open`, `openat2` and `execveat` paths are not hooked.
- Exe/args/parent are only known for processes started after the agent. Older processes get `comm` and pid only.
- Detection is per event (no sequences or time windows). There are no `not` conditions, no central server, and no tamper protection.
- Kernel 7.x BTF needs clang `-fms-extensions` (set in `gen.go`).
