#!/bin/bash
# Title: PagerSploit
# Description: Full wireless pentest framework with browser-based UI. Connect via USB-C or management AP at 172.16.52.1:8080. WiFi attacks, LAN recon, credential capture, handshake cracking, evil portal, and live loot — all from your phone.
# Author: wickedNull
# Version: 1.0
# Category: Interception

# The Pager framework copies payload.sh to /tmp before running, so $0 is
# /tmp/payload.sh and dirname/$0 is useless. Search known install paths instead.
PAYLOAD_DIR=""
for _try in \
    "/root/payloads/user/interception/PagerSploit" \
    "/root/payloads/user/interception/pagersploit" \
    "/root/payloads/user/interception/PagerSploit-main" \
    "/root/payloads/interception/PagerSploit" \
    "/root/payloads/interception/pagersploit" \
    "/root/payloads/interception/PagerSploit-main" \
    "/mmc/root/payloads/user/interception/PagerSploit" \
    "/mmc/root/payloads/user/interception/pagersploit" \
    "/mmc/root/payloads/user/interception/PagerSploit-main" \
    "/mmc/root/payloads/interception/PagerSploit" \
    "/mmc/root/payloads/interception/pagersploit" \
    "/mmc/root/payloads/interception/PagerSploit-main" \
    "/mmc/payloads/user/interception/PagerSploit" \
    "/mmc/payloads/user/interception/pagersploit" \
    "/mmc/payloads/interception/PagerSploit" \
    "/mmc/payloads/interception/pagersploit"; do
    if [ -f "$_try/pagersploit.py" ]; then
        PAYLOAD_DIR="$_try"
        break
    fi
done
if [ -z "$PAYLOAD_DIR" ]; then
    LOG "red" "Cannot find PagerSploit install directory"
    LOG "red" "Expected pagersploit.py in one of:"
    LOG "yellow" "  /root/payloads/user/interception/PagerSploit"
    LOG "yellow" "  /mmc/root/payloads/user/interception/PagerSploit"
    WAIT_FOR_INPUT >/dev/null 2>&1; exit 1
fi
LOG_FILE="/tmp/pagersploit.log"
SERVER_IP="172.16.52.1"
SERVER_PORT="8080"

# -- Check for bundled pagerctl (ships in payload lib/) -----------------------
# pagerctl.py + libpagerctl.so must be in $PAYLOAD_DIR/lib/.
# They are included in the PagerSploit release — no opkg needed.
PAGERCTL_LIB="$PAYLOAD_DIR/lib"
if [ -f "$PAGERCTL_LIB/libpagerctl.so" ] && [ -f "$PAGERCTL_LIB/pagerctl.py" ]; then
    PAGERCTL_FOUND=true
else
    PAGERCTL_FOUND=false
    # Also check the Hak5 PAGERCTL utility location in case user installed it separately
    for _d in "/root/payloads/user/utilities/PAGERCTL" \
              "/mmc/root/payloads/user/utilities/PAGERCTL" \
              "/usr/lib" "/usr/local/lib"; do
        if [ -f "$_d/libpagerctl.so" ] && [ -f "$_d/pagerctl.py" ]; then
            mkdir -p "$PAGERCTL_LIB" 2>/dev/null
            cp "$_d/libpagerctl.so" "$PAGERCTL_LIB/" 2>/dev/null
            cp "$_d/pagerctl.py"    "$PAGERCTL_LIB/" 2>/dev/null
            PAGERCTL_FOUND=true
            break
        fi
    done
fi

if [ "$PAGERCTL_FOUND" = false ]; then
    LOG "yellow" "pagerctl not in lib/ — screen disabled, web UI still works"
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

# Wait for GREEN/A to launch, RED/B to exit.
# WAIT_FOR_INPUT is a Pager shell built-in. If it returns empty (function
# unavailable or button not recognised), auto-start after 3 empty replies
# so the payload never hangs waiting for a button that never arrives.
_btn_wait() {
    local empty=0 tries=0
    while [ $tries -lt 120 ]; do
        BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
        case "$BUTTON" in
            GREEN|A|BTN_A|BUTTON_A|16|0x10) return 0 ;;  # launch
            RED|B|BTN_B|BUTTON_B|32|0x20)   return 1 ;;  # exit
        esac
        # Empty/unrecognised → WAIT_FOR_INPUT not blocking or not present.
        # After 3 consecutive empty results, auto-start.
        if [ -z "$BUTTON" ]; then
            empty=$((empty+1))
            [ $empty -ge 3 ] && { LOG "yellow" "(auto-starting — button unavailable)"; return 0; }
            sleep 0.5
        else
            empty=0  # got a value but didn't match; keep waiting
        fi
        tries=$((tries+1))
    done
    LOG "yellow" "(timeout — auto-starting)"
    return 0
}

if ! _btn_wait; then
    LOG "Exiting."
    exit 0
fi

# -- Create directories --------------------------------------------------------
mkdir -p "$PAYLOAD_DIR/loot/handshakes" \
         "$PAYLOAD_DIR/loot/credentials" \
         "$PAYLOAD_DIR/loot/scans" \
         "$PAYLOAD_DIR/loot/pmkid" \
         "$PAYLOAD_DIR/wordlists" \
         "$PAYLOAD_DIR/portals" \
         "$PAYLOAD_DIR/lib" 2>/dev/null

# -- No service teardown needed ------------------------------------------------
# pineapplepager: leave running — stopping it triggers a watchdog reboot.
#   pagerctl drives the display directly alongside pineapplepager.
# nginx / php8-fpm: leave running — we use port 8080, no conflict.
# pineapd: always left running — owns recon.db and radio hopping.

# -- Pre-flight checks ---------------------------------------------------------
LOG "white" "PAYLOAD_DIR: $PAYLOAD_DIR"

if [ -z "$PYTHON" ]; then
    LOG "red" "python3 not found in PATH"
    WAIT_FOR_INPUT >/dev/null 2>&1; exit 1
fi

if [ ! -f "$PAYLOAD_DIR/pagersploit.py" ]; then
    LOG "red" "pagersploit.py not found at:"
    LOG "red" "  $PAYLOAD_DIR/pagersploit.py"
    LOG "yellow" "Check that all payload files were copied to the Pager"
    WAIT_FOR_INPUT >/dev/null 2>&1; exit 1
fi

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
    if [ -f /tmp/pagersploit_url.txt ]; then
        LOG "green" "UI was at: $(cat /tmp/pagersploit_url.txt)"
    fi
    LOG "white" "Last log lines:"
    tail -5 "$LOG_FILE" 2>/dev/null | while IFS= read -r line; do
        LOG "yellow" "  $line"
    done
    LOG ""
    LOG "Press any button..."
    WAIT_FOR_INPUT >/dev/null 2>&1
fi

