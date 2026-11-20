# EDR MVP — Linux eBPF agent

Objective: minimal Endpoint Detection and Response agent for Linux using eBPF telemetry, a rule engine, and response actions.
Branch: `feat/edr-mvp` · Delivery: ask-on-risk · Test runner: `go test ./...` inside the Docker dev image (`make test`); eBPF e2e via `make e2e` (privileged container).

## Specs

- S1 (user choice) Platform: "Linux + eBPF (Recommended)" — "Telemetría real desde el kernel (exec, open, connect) con eBPF. Go como agente."
- S2 (assumption) Telemetry: kernel probes capture process exec, process exit, file open (`openat`), and outbound network connect (IPv4/IPv6), with pid, ppid, uid, comm, and the event-specific fields (filename/argv, path/flags, address/port).
- S3 (assumption) Events are normalized into a kernel-independent domain model and written as JSON Lines (stdout or file).
- S4 (assumption) Detection: YAML rules with field conditions (`equals`, `contains`, `startswith`, `endswith`, `in`) combined with AND; a match emits an alert with rule id, severity, and the triggering event.
- S5 (assumption) Response: a rule may declare `action: kill`; the agent terminates the offending process unless `--dry-run` is set; the result is recorded on the alert.
- S6 (assumption) Build and run fully inside Docker (no Go needed on the macOS host): `make build`, `make test`, `make run`, `make e2e`.
- S7 (assumption) Architecture: hexagonal; domain and detection have no eBPF or IO dependencies and are unit-tested with fakes.

## Tasks

- [x] T1 S3,S6,S7 — scaffold, dev image, domain model, JSONL sink · route: inline
- [x] T2 S4,S7 — rule engine + YAML loader + default rules · route: inline
- [x] T3 S5 — response (kill) + dry-run · route: inline
- [x] T4 S2 — eBPF probes (C) + Go loader adapter · route: inline
- [x] T5 S2-S6 — agent wiring (cmd) + e2e in privileged container + README · route: inline

Route evidence: single sequential dependency chain, no parallel units → no Writer trigger; all inline.

## Log

- L1 (2026-11-20) User: "Construyamos un Endpoint Detection and Response (EDR)"
- L2 (2026-11-20) User chose "Linux + eBPF (Recommended)".
- L3 Env: no Go on host; Docker Desktop 29.8.0, kernel 7.0.12-linuxkit aarch64, BTF present, tracepoints sys_enter_{execve,openat,connect} and sched_process_{exec,exit,fork} available.
- L4 T4: kernel 7.0 BTF uses MS-style anonymous struct members; clang 14 needs `-fms-extensions -Wno-microsoft-anon-tag` (dropping them would corrupt struct layouts). Containers lack tracefs: sensor mounts it when missing. Agent must run with `--pid=host` so BPF pids match kill targets. e2e (exec/open/connect/exit + self-filter) PASS on 7.0.12-linuxkit arm64.
- L5 T5: `make test` PASS (7 pkgs); `make e2e` PASS — sensor tests + agent_e2e.sh (EDR-001 kill 137, EDR-003, EDR-004, EDR-005); `make image-runtime` builds (146MB). Commits: T1 6ccace7, T2 7617d44, T3 b5b8a40, T4 27ceece, T5 see git log.
- L6 (2026-11-20) User: "haz el push y crea el repo en github por favor, y haz el paso reomendado despues de eso". Repo created private: github.com/ignacioaguayluz/edr (main + feat/edr-mvp pushed). Branch fix/review-advisories fixes advisories R1-001 (EDR-002 no longer kills node children), R1-002/R3/R4 ringbuf drops (per-CPU drop counter + periodic warning), R3-missing-rules-dir-silent, R3-multidoc-yaml-ignored. RED observed for all; make test + make e2e PASS (31673 drops counted under flood).
- L7 (2026-11-20) User: "hazlo publico por favor, añade el .atl y el .claude al gitignore por favor, haz los pendientes por favor". Repo made public. .atl/ and .claude/ ignored. R3-self-filter-test-vacuous fixed with before/after child control markers; mutation check (agent_tgid=0) makes it FAIL, restored code PASSES; make test + make e2e PASS.
