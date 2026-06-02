#!/usr/bin/env bash
# stress_test.sh — 20 concurrent clients, 50 messages each, 1 receiver
# Pass condition: all sender processes exit 0 and server stays alive

set -euo pipefail

BINARY_SERVER="./bin/server"
BINARY_CLIENT="./bin/client"
HOST="localhost"
PORT="8080"
N_SENDERS=20
N_MSGS=50
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── Build ──────────────────────────────────────────────────────────────────
echo "=== Stress Test: ${N_SENDERS} clients × ${N_MSGS} messages ==="
echo ""
echo "[1/4] Building..."
make clean-all > /dev/null 2>&1
make certs     > /dev/null 2>&1
make all       > /dev/null 2>&1
make tests     > /dev/null 2>&1
echo "      Build OK"

# ── Start server ──────────────────────────────────────────────────────────
echo "[2/4] Starting server..."
mkdir -p data/offline_queue
"$BINARY_SERVER" > /tmp/aschat_stress_server.log 2>&1 &
SERVER_PID=$!
sleep 0.5

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: Server did not start (see /tmp/aschat_stress_server.log)"
    exit 1
fi
echo "      Server PID=$SERVER_PID OK"

# ── Start receiver ────────────────────────────────────────────────────────
echo "[3/4] Starting receiver client..."
(sleep 30) | "$BINARY_CLIENT" "$HOST" "$PORT" stress_receiver \
    > /tmp/aschat_stress_receiver.log 2>&1 &
RECEIVER_PID=$!
sleep 0.3

# ── Launch senders ────────────────────────────────────────────────────────
echo "[4/4] Launching ${N_SENDERS} sender clients..."
declare -a SENDER_PIDS
FAIL=0

for i in $(seq 1 "$N_SENDERS"); do
    {
        for j in $(seq 1 "$N_MSGS"); do
            printf '@stress_receiver stress_msg_%d_%d\n' "$i" "$j"
        done
        printf '/quit\n'
    } | "$BINARY_CLIENT" "$HOST" "$PORT" "sender_${i}" \
          > "/tmp/aschat_stress_sender_${i}.log" 2>&1 &
    SENDER_PIDS+=($!)
done

echo "      Waiting for ${N_SENDERS} senders to complete..."

for i in "${!SENDER_PIDS[@]}"; do
    pid="${SENDER_PIDS[$i]}"
    if ! wait "$pid"; then
        echo "      WARN: sender_$((i+1)) (PID $pid) exited non-zero"
        FAIL=$((FAIL + 1))
    fi
done

# ── Validate ──────────────────────────────────────────────────────────────
echo ""
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: Server crashed during stress test (see /tmp/aschat_stress_server.log)"
    FAIL=$((FAIL + 1))
else
    echo "Server still running after stress test: OK"
fi

kill "$RECEIVER_PID" 2>/dev/null || true
wait "$RECEIVER_PID" 2>/dev/null || true

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "=== PASS: All ${N_SENDERS} clients completed without errors ==="
    exit 0
else
    echo "=== FAIL: ${FAIL} client(s) had errors ==="
    echo "Logs: /tmp/aschat_stress_sender_*.log"
    exit 1
fi
