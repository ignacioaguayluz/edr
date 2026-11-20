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
- [x] T2 — independent verifier (Risk item 2: kill guard) · route: delegated

## Log

- L1 (2026-11-20) User: "implementa el kill con pidfd por favor"
- L2 T1: RED observed (undefined pidfdKill/procStartTicks/StartNs); GREEN: make test PASS incl. real pidfd tests (kill matching instance, spare mismatched start, ESRCH on exited); make e2e PASS (miner killed via pidfd, StartBootNS>0 asserted).
- L3 T2: independent verifier — S1-S4 PASS, no blockers; invariant (dry-run alerts identical vs main except new start_boottime_ns) PASS. Native review (reliability lens) approved + acknowledged, lineage review-a420e3e8f57dedcf. Follow-ups: verifier probe committed as test/e2e/identity_test.go (thread + de_thread exec start time == /proc, then pidfd kill); flaky ESRCH test now uses pid > PID_MAX_LIMIT; README documents 10 ms resolution and kernel >= 5.8. make test + make e2e PASS.
- Open advisory (not in scope): agent process table is keyed by pid only; a dropped exit event lets a reused pid inherit stale exe/args, so a rule could match and kill the new process. Guarding the lookup with StartBootNS would fix it.
