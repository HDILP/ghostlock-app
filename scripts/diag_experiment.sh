#!/system/bin/sh
# GhostLock PJJ110 — Parent Identification Experiment
#
# Usage: push to device, then run:
#   sh /data/local/tmp/ghostlock_diag.sh
#
# Environment variables:
#   GHOSTLOCK_CONSUMER_NICE  — consumer priority (default -20)
#   GHOSTLOCK_WAITER_NICE    — waiter priority (default -10)
#
# Experiment matrix:
#   Round 1-5:  consumer_nice=-20 (prio 100) — baseline
#   Round 6-10: consumer_nice=0   (prio 120) — same as owner
#   Round 11-15: consumer_nice=5  (prio 125) — lower than owner

BIN="/data/local/tmp/ghostlock"
LOG_DIR="/sdcard/Download"
DIAG_LOG="$LOG_DIR/ghostlock_diag.txt"
PUNCH_LOG="$LOG_DIR/ghostlock_punch_seq"

# Clear previous logs
rm -f "$DIAG_LOG" "$PUNCH_LOG"

echo "=== Parent Identification Experiment ===" | tee -a "$DIAG_LOG"
echo "Date: $(date)" | tee -a "$DIAG_LOG"
echo "" | tee -a "$DIAG_LOG"

# Phase 1: Baseline — consumer nice=-20 (high priority)
echo "--- Phase 1: consumer_nice=-20 (baseline, 5 rounds) ---" | tee -a "$DIAG_LOG"
for i in 1 2 3 4 5; do
    echo "Round $i/5 (consumer_nice=-20)" | tee -a "$DIAG_LOG"
    GHOSTLOCK_CONSUMER_NICE=-20 GHOSTLOCK_WAITER_NICE=-10 "$BIN" 2>&1 | tee -a "$DIAG_LOG"
    echo "---" | tee -a "$DIAG_LOG"
    sleep 2
done

# Phase 2: Consumer at owner priority — consumer nice=0
echo "" | tee -a "$DIAG_LOG"
echo "--- Phase 2: consumer_nice=0 (owner prio, 5 rounds) ---" | tee -a "$DIAG_LOG"
for i in 1 2 3 4 5; do
    echo "Round $i/5 (consumer_nice=0)" | tee -a "$DIAG_LOG"
    GHOSTLOCK_CONSUMER_NICE=0 GHOSTLOCK_WAITER_NICE=-10 "$BIN" 2>&1 | tee -a "$DIAG_LOG"
    echo "---" | tee -a "$DIAG_LOG"
    sleep 2
done

# Phase 3: Consumer lower than owner — consumer nice=5
echo "" | tee -a "$DIAG_LOG"
echo "--- Phase 3: consumer_nice=5 (lower prio, 5 rounds) ---" | tee -a "$DIAG_LOG"
for i in 1 2 3 4 5; do
    echo "Round $i/5 (consumer_nice=5)" | tee -a "$DIAG_LOG"
    GHOSTLOCK_CONSUMER_NICE=5 GHOSTLOCK_WAITER_NICE=-10 "$BIN" 2>&1 | tee -a "$DIAG_LOG"
    echo "---" | tee -a "$DIAG_LOG"
    sleep 2
done

echo "" | tee -a "$DIAG_LOG"
echo "=== Experiment complete ===" | tee -a "$DIAG_LOG"
echo "Results: $DIAG_LOG" | tee -a "$DIAG_LOG"
echo "Punch log: $PUNCH_LOG"
