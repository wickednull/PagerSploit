#!/bin/bash
# Title: PagerSploit
# Description: Full wireless pentest framework with browser-based UI. Connect via USB-C or management AP at 172.16.52.1:8080. WiFi attacks, LAN recon, credential capture, handshake cracking, evil portal, and live loot — all from your phone.
# Author: wickedNull
# Version: 1.0
# Category: Interception

PAYLOAD_DIR="/root/payloads/user/interception/PagerSploit"
LOG_FILE="/tmp/pagersploit.log"
SERVER_IP="172.16.52.1"
SERVER_PORT="8080"

# -- Find pagerctl -------------------------------------------------------------
PAGERCTL_FOUND=false
for dir in "$PAYLOAD_DIR/lib" \
           "/root/payloads/user/utilities/PAGERCTL" \
           "/mmc/root/payloads/user/utilities/PAGERCTL"; do
    if [ -f "$dir/libpagerctl.so" ] && [ -f "$dir/pagerctl.py" ]; then
        PAGERCTL_DIR="$dir"
        PAGERCTL_FOUND=true
        break
    fi
done

if [ "$PAGERCTL_FOUND" = false ]; then
    LOG "red" "libpagerctl.so / pagerctl.py not found!"
    LOG "Install PAGERCTL utility or copy files to:"
    LOG "  $PAYLOAD_DIR/lib/"
    WAIT_FOR_INPUT >/dev/null 2>&1
    exit 1
fi

if [ "$PAGERCTL_DIR" != "$PAYLOAD_DIR/lib" ]; then
    mkdir -p "$PAYLOAD_DIR/lib" 2>/dev/null
    cp "$PAGERCTL_DIR/libpagerctl.so" "$PAYLOAD_DIR/lib/" 2>/dev/null
    cp "$PAGERCTL_DIR/pagerctl.py"    "$PAYLOAD_DIR/lib/" 2>/dev/null
fi

export PATH="/mmc/usr/bin:/mmc/usr/sbin:$PAYLOAD_DIR/bin:$PATH"
export LD_LIBRARY_PATH="/mmc/usr/lib:/mmc/lib:$PAYLOAD_DIR/lib:$LD_LIBRARY_PATH"
export PYTHONPATH="$PAYLOAD_DIR/lib:$PAYLOAD_DIR:$PYTHONPATH"

PYTHON=$(command -v python3)

# -- Splash --------------------------------------------------------------------
LOG ""
LOG "cyan"  "  ░░ P A G E R S P L O I T ░░"
LOG ""
LOG "white" "Pentest Framework // WiFi Pineapple Pager"
LOG ""
LOG "green" "UI at: http://$SERVER_IP:$SERVER_PORT"
LOG "cyan"  "Connect via USB-C ethernet or management AP"
LOG ""
LOG "green" "GREEN = Launch"
LOG "red"   "RED   = Exit"
LOG ""

while true; do
    BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
    case "$BUTTON" in
        "GREEN"|"A") break ;;
        "RED"|"B")
            LOG "Exiting."
            exit 0
            ;;
    esac
done

# -- Create directories --------------------------------------------------------
mkdir -p "$PAYLOAD_DIR/loot/handshakes" \
         "$PAYLOAD_DIR/loot/credentials" \
         "$PAYLOAD_DIR/loot/scans" \
         "$PAYLOAD_DIR/loot/pmkid" \
         "$PAYLOAD_DIR/wordlists" \
         "$PAYLOAD_DIR/portals" \
         "$PAYLOAD_DIR/lib" 2>/dev/null

# -- Stop services -------------------------------------------------------------
SPINNER_ID=$(START_SPINNER "Initializing PagerSploit...")
# pineapplepager/pineapd left running intentionally — PagerSploit reads recon.db
# which is only populated while pineapd is active and channel-hopping
/etc/init.d/php8-fpm       stop 2>/dev/null
/etc/init.d/nginx          stop 2>/dev/null
/etc/init.d/bluetoothd     stop 2>/dev/null
sleep 0.5
STOP_SPINNER "$SPINNER_ID" 2>/dev/null

# -- Launch --------------------------------------------------------------------
"$PYTHON" "$PAYLOAD_DIR/pagersploit.py" \
    --server-ip   "$SERVER_IP" \
    --server-port "$SERVER_PORT" \
    --payload-dir "$PAYLOAD_DIR" \
    > "$LOG_FILE" 2>&1

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    LOG ""
    LOG "red" "PagerSploit exited with error (code $EXIT_CODE)"
    LOG "Check /tmp/pagersploit.log"
    LOG ""
    LOG "Press any button..."
    WAIT_FOR_INPUT >/dev/null 2>&1
fi

sleep 0.5

# -- Restore services ----------------------------------------------------------
/etc/init.d/bluetoothd     start 2>/dev/null &
/etc/init.d/nginx          start 2>/dev/null &
/etc/init.d/php8-fpm       start 2>/dev/null &
# pineapplepager was not stopped, no need to restart
