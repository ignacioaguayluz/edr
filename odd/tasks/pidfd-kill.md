# pidfd-based kill response

Objective: close the PID-reuse race in the kill response by targeting the exact process instance (pid + start time) through a pidfd.
Branch: `feat/pidfd-kill` · Delivery: single PR to main · Test runner: `make test`, `make e2e`.

## Specs

- S1 User: "implementa el kill con pidfd por favor"
- S2 (assumption) The kernel sensor reports each process's start time (`group_leader->start_boottime`) on every event.
- S3 (assumption) The responder opens a pidfd, verifies the process start time against `/proc/<pid>/stat` and only then signals through `pidfd_send_signal`. A mismatch reports `gone` with error "pid reused by another process" and sends no signal.
- S4 (assumption) An alert without a known start time is not killed (fail closed: `skipped`, "process identity unknown").

## Tasks

- [x] T1 S2-S4 — BPF start time, event model, pidfd killer, tests, README · route: inline (one unit, ~150 lines)
- [ ] T2 — independent verifier (Risk item 2: kill guard) · route: delegated

## Log

- L1 (2026-11-20) User: "implementa el kill con pidfd por favor"
- L2 T1: RED observed (undefined pidfdKill/procStartTicks/StartNs); GREEN: make test PASS incl. real pidfd tests (kill matching instance, spare mismatched start, ESRCH on exited); make e2e PASS (miner killed via pidfd, StartBootNS>0 asserted).
