#!/bin/bash
# Title: PagerSploit v2.9
# Description: Pure-Native Pentest Framework (Zero Dependencies)

PAYLOAD_DIR=$(dirname "$(readlink -f "$0")")
PYTHON="python3"
LOG_FILE="/tmp/pagersploit.log"

# -- Setup ---------------------------------------------------------------------
mkdir -p "$PAYLOAD_DIR/loot/handshakes" \
         "$PAYLOAD_DIR/loot/credentials" \
         "$PAYLOAD_DIR/loot/scans" \
         "$PAYLOAD_DIR/loot/reports" 2>/dev/null

# -- Stop services -------------------------------------------------------------
# We only stop the official UI to free the screen buffer.
# pineapd remains running as our primary attack engine.
/etc/init.d/pineapplepager stop 2>/dev/null
sleep 1

# -- Launch --------------------------------------------------------------------
# Pass payload dir so python knows where to save loot
"$PYTHON" "$PAYLOAD_DIR/pagersploit.py" \
    --payload-dir "$PAYLOAD_DIR" \
    > "$LOG_FILE" 2>&1

# -- Restore services ----------------------------------------------------------
/etc/init.d/pineapplepager start 2>/dev/null &
