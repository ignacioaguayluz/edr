#!/usr/bin/env bash
# End-to-end test of the full agent: real kernel telemetry, shipped rules,
# real kill response. Must run as root in the host pid namespace (make e2e).
set -euo pipefail

BIN=${BIN:-./bin/edr-agent}
WORK=$(mktemp -d)
OUT="$WORK/alerts.jsonl"
LOG="$WORK/agent.log"
AGENT_PID=""
FAILED=0

cleanup() {
  [[ -n "$AGENT_PID" ]] && kill "$AGENT_PID" 2>/dev/null && wait "$AGENT_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

check() { # check <description> <jq filter that must select at least one alert>
  if jq -e -s "map(select(.type == \"alert\" and ($2))) | length > 0" "$OUT" >/dev/null; then
    echo "PASS  $1"
  else
    echo "FAIL  $1"; FAILED=1
  fi
}

"$BIN" --rules rules --output "$OUT" 2>"$LOG" &
AGENT_PID=$!
for _ in $(seq 1 50); do grep -q "agent started" "$LOG" && break; sleep 0.1; done
grep -q "agent started" "$LOG" || { cat "$LOG"; echo "FAIL  agent did not start"; exit 1; }

# EDR-001 + EDR-005: a "miner" executed from /tmp must be killed.
mkdir -p "$WORK/bin" && cp /bin/sleep "$WORK/bin/xmrig"
set +e; "$WORK/bin/xmrig" 30; MINER_STATUS=$?; set -e
if [[ $MINER_STATUS -eq 137 ]]; then echo "PASS  miner terminated by SIGKILL"; else echo "FAIL  miner exit status $MINER_STATUS"; FAILED=1; fi

# EDR-004: credential store read.
cat /etc/shadow >/dev/null

# EDR-003: reverse-shell port (connection refused is fine; the attempt is what we detect).
bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444' 2>/dev/null || true

sleep 1
check "EDR-001 miner alert with kill response" '.data.rule_id == "EDR-001" and .data.event.process.comm == "xmrig" and .data.response.status == "killed"'
check "EDR-005 exec from /tmp"                '.data.rule_id == "EDR-005" and (.data.event.process.exe | endswith("/bin/xmrig"))'
check "EDR-004 /etc/shadow read by cat"       '.data.rule_id == "EDR-004" and .data.event.process.comm == "cat"'
check "EDR-003 connect to port 4444"          '.data.rule_id == "EDR-003" and .data.event.network.dst_port == 4444'

if [[ $FAILED -ne 0 ]]; then echo "--- agent log"; cat "$LOG"; echo "--- output"; cat "$OUT"; exit 1; fi
echo "agent e2e: all checks passed"
