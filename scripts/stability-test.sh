#!/usr/bin/env bash
# Overnight stability test using the Docker harness.
#
# Starts the vpn-server + vpn-client + target stack, then runs a probe every
# INTERVAL seconds for DURATION seconds (default: 8 hours). On exit — whether
# from timeout, Ctrl-C, or failure — prints a summary report and tears down
# the stack.
#
# Usage:
#
#   ./scripts/stability-test.sh                      # 8 h, 60 s interval
#   DURATION=3600 INTERVAL=30 ./scripts/stability-test.sh
#
# Output:
#
#   logs/stability-<timestamp>/
#     run.log       full timestamped log of every probe
#     server.log    javs server logs captured from the container
#     summary.txt   final report (also printed to stdout)
#
# Requirements: docker + docker compose.
#
set -euo pipefail

DURATION="${DURATION:-28800}"   # seconds to run  (default 8 h)
INTERVAL="${INTERVAL:-60}"      # seconds between probes
PING_COUNT="${PING_COUNT:-3}"   # pings per probe

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_DIR="logs/stability-$TIMESTAMP"
mkdir -p "$LOG_DIR"
RUN_LOG="$LOG_DIR/run.log"
SUMMARY="$LOG_DIR/summary.txt"

# ── helpers ──────────────────────────────────────────────────────────────────

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$RUN_LOG"; }
log_raw() { echo "$*" | tee -a "$RUN_LOG"; }

# ── counters ─────────────────────────────────────────────────────────────────

TOTAL=0
PASS=0
FAIL=0
RECONNECTS=0
declare -a FAILURES=()

# ── cleanup on exit ───────────────────────────────────────────────────────────

cleanup() {
    local exit_code=$?
    log "--- tearing down stack ---"
    docker compose -f docker/docker-compose.yml logs vpn-server \
        > "$LOG_DIR/server.log" 2>&1 || true
    docker compose -f docker/docker-compose.yml down -v --remove-orphans \
        >> "$RUN_LOG" 2>&1 || true

    write_summary
    echo
    cat "$SUMMARY"
    exit $exit_code
}
trap cleanup EXIT

# ── summary report ────────────────────────────────────────────────────────────

write_summary() {
    local end_ts; end_ts=$(date '+%Y-%m-%d %H:%M:%S')
    local elapsed=$(( $(date +%s) - START_TS ))
    local h=$(( elapsed / 3600 ))
    local m=$(( (elapsed % 3600) / 60 ))
    local s=$(( elapsed % 60 ))
    local rate=0
    [[ $TOTAL -gt 0 ]] && rate=$(( PASS * 100 / TOTAL ))

    {
        echo "========================================"
        echo "  javs stability-test summary"
        echo "========================================"
        echo "  Started : $START_TIME"
        echo "  Ended   : $end_ts"
        echo "  Elapsed : ${h}h ${m}m ${s}s"
        echo "  Interval: ${INTERVAL}s"
        echo "----------------------------------------"
        echo "  Probes  : $TOTAL"
        echo "  Pass    : $PASS"
        echo "  Fail    : $FAIL"
        echo "  Success : ${rate}%"
        echo "  Reconnects detected: $RECONNECTS"
        echo "----------------------------------------"
        if [[ ${#FAILURES[@]} -gt 0 ]]; then
            echo "  Failed probes:"
            for f in "${FAILURES[@]}"; do
                echo "    $f"
            done
        else
            echo "  No failures."
        fi
        echo "========================================"
        echo "  Logs: $LOG_DIR/"
        echo "========================================"
    } | tee "$SUMMARY"
}

# ── PKI / PSK bootstrap ───────────────────────────────────────────────────────

if [[ ! -f configs/pki/ca.crt ]]; then
    log "generating PKI (configs/pki was empty)"
    bash scripts/generate-certs.sh
fi

if [[ ! -f configs/pki/tc.key ]]; then
    log "generating tls-crypt static key"
    bash scripts/generate-psk.sh configs/pki/tc.key
fi

# ── bring up the stack ────────────────────────────────────────────────────────

log "building + starting docker stack"
docker compose -f docker/docker-compose.yml up --build -d >> "$RUN_LOG" 2>&1

log "waiting up to 90s for client tunnel to come up"
for i in $(seq 1 90); do
    if docker compose -f docker/docker-compose.yml logs vpn-client 2>&1 \
            | grep -q "Initialization Sequence Completed"; then
        log "client tunnel up after ${i}s"
        break
    fi
    sleep 1
    if [[ $i -eq 90 ]]; then
        log "ERROR: client never came up — aborting"
        docker compose -f docker/docker-compose.yml logs >> "$RUN_LOG" 2>&1
        exit 1
    fi
done

# ── probe loop ────────────────────────────────────────────────────────────────

START_TS=$(date +%s)
START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
END_TS=$(( START_TS + DURATION ))
PREV_RECONNECTS=0

log "stability test started — running for ${DURATION}s ($(( DURATION / 3600 ))h $(( (DURATION % 3600) / 60 ))m)"
log "logs → $LOG_DIR/"
log_raw ""

while [[ $(date +%s) -lt $END_TS ]]; do
    PROBE_START=$(date +%s)
    PROBE_TIME=$(date '+%H:%M:%S')
    TOTAL=$(( TOTAL + 1 ))
    probe_ok=true
    probe_notes=""

    # 1. IPv4 ping to server TUN
    if ! docker compose -f docker/docker-compose.yml exec -T vpn-client \
            ping -c "$PING_COUNT" -W 3 10.8.0.1 >> "$RUN_LOG" 2>&1; then
        probe_ok=false
        probe_notes+=" ping4-fail"
    fi

    # 2. IPv6 ping to server TUN
    if ! docker compose -f docker/docker-compose.yml exec -T vpn-client \
            ping -6 -c "$PING_COUNT" -W 3 fd00:beef::1 >> "$RUN_LOG" 2>&1; then
        probe_ok=false
        probe_notes+=" ping6-fail"
    fi

    # 3. curl internal target (only reachable via NAT through the tunnel)
    if ! docker compose -f docker/docker-compose.yml exec -T vpn-client \
            curl -sS --max-time 5 http://10.98.0.3:8080/ >> "$RUN_LOG" 2>&1; then
        probe_ok=false
        probe_notes+=" nat-fail"
    fi

    # 4. check for reconnects since last probe (count "Initialization Sequence Completed")
    CUR_RECONNECTS=$(docker compose -f docker/docker-compose.yml logs vpn-client 2>&1 \
        | grep -c "Initialization Sequence Completed" || true)
    NEW_RECONNECTS=$(( CUR_RECONNECTS - PREV_RECONNECTS ))
    RECONNECTS=$(( RECONNECTS + NEW_RECONNECTS ))
    PREV_RECONNECTS=$CUR_RECONNECTS
    [[ $NEW_RECONNECTS -gt 0 ]] && probe_notes+=" reconnects:+${NEW_RECONNECTS}"

    # 5. server memory usage
    MEM=$(docker compose -f docker/docker-compose.yml exec -T vpn-server \
        sh -c 'cat /proc/$(pgrep javs)/status 2>/dev/null | grep VmRSS' \
        2>/dev/null | awk '{print $2, $3}' || echo "?")

    # record result
    ELAPSED=$(( $(date +%s) - START_TS ))
    EL_H=$(( ELAPSED / 3600 ))
    EL_M=$(( (ELAPSED % 3600) / 60 ))

    if $probe_ok; then
        PASS=$(( PASS + 1 ))
        log "probe #${TOTAL} [${EL_H}h${EL_M}m] PASS  mem=${MEM}${probe_notes}"
    else
        FAIL=$(( FAIL + 1 ))
        FAILURES+=( "#${TOTAL} ${PROBE_TIME}${probe_notes}" )
        log "probe #${TOTAL} [${EL_H}h${EL_M}m] FAIL${probe_notes}  mem=${MEM}"
    fi

    # sleep for the remainder of INTERVAL
    PROBE_ELAPSED=$(( $(date +%s) - PROBE_START ))
    SLEEP=$(( INTERVAL - PROBE_ELAPSED ))
    [[ $SLEEP -gt 0 ]] && sleep "$SLEEP"
done

log "duration reached — test complete"
