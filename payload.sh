#!/bin/bash
# TITLE: PagerSploit
# DESCRIPTION: Wireless Pentest Framework with Browser UI.
# AUTHOR: wickedNull
# VERSION: 2.1
# CATEGORY: Interception

# Source Pineapple functions for Pager-native commands
if [ -f /lib/pineapple/functions ]; then
    source /lib/pineapple/functions
elif [ -f /etc/pineapple/functions ]; then
    source /etc/pineapple/functions
fi

# Dynamic Payload Directory
PAYLOAD_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOG_FILE="/tmp/pagersploit.log"
SERVER_IP="172.16.52.1"
SERVER_PORT="8080"

# -- Cleanup function ----------------------------------------------------------
function finish() {
    LOG "Restoring services..."
    /etc/init.d/bluetoothd     start 2>/dev/null &
    /etc/init.d/nginx          start 2>/dev/null &
    /etc/init.d/php8-fpm       start 2>/dev/null &
    /etc/init.d/pineapplepager start 2>/dev/null &
    VIBRATE
}
trap finish EXIT

# -- Find pagerctl -------------------------------------------------------------
PAGERCTL_FOUND=false
for dir in "$PAYLOAD_DIR/lib" \
           "/root/payloads/user/utilities/PAGERCTL" \
           "/mmc/root/payloads/user/utilities/PAGERCTL" \
           "/root/payloads/user/General/PAGERCTL"; do
    if [ -f "$dir/libpagerctl.so" ] && [ -f "$dir/pagerctl.py" ]; then
        PAGERCTL_DIR="$dir"
        PAGERCTL_FOUND=true
        break
    fi
done

if [ "$PAGERCTL_FOUND" = false ]; then
    ERROR_DIALOG "PAGERCTL not found! Please install it via the Pager UI or copy pagerctl.py/libpagerctl.so to PagerSploit/lib/"
    exit 1
fi

if [ "$PAGERCTL_DIR" != "$PAYLOAD_DIR/lib" ]; then
    mkdir -p "$PAYLOAD_DIR/lib"
    cp "$PAGERCTL_DIR/libpagerctl.so" "$PAYLOAD_DIR/lib/"
    cp "$PAGERCTL_DIR/pagerctl.py"    "$PAYLOAD_DIR/lib/"
fi

export PATH="/mmc/usr/bin:/mmc/usr/sbin:$PAYLOAD_DIR/bin:$PATH"
export LD_LIBRARY_PATH="/mmc/usr/lib:/mmc/lib:$PAYLOAD_DIR/lib:$LD_LIBRARY_PATH"
export PYTHONPATH="$PAYLOAD_DIR/lib:$PAYLOAD_DIR:$PYTHONPATH"

PYTHON=$(command -v python3)

# -- Splash --------------------------------------------------------------------
CONFIRMATION_DIALOG "PagerSploit" "Launch PagerSploit Framework?\n\nUI: http://$SERVER_IP:$SERVER_PORT"
if [ $? -ne 0 ]; then
    exit 0
fi

# -- Create directories --------------------------------------------------------
mkdir -p "$PAYLOAD_DIR/loot/handshakes" \
         "$PAYLOAD_DIR/loot/credentials" \
         "$PAYLOAD_DIR/loot/scans" \
         "$PAYLOAD_DIR/loot/pmkid" \
         "$PAYLOAD_DIR/wordlists" \
         "$PAYLOAD_DIR/portals" \
         "$PAYLOAD_DIR/lib"

# -- Stop services -------------------------------------------------------------
SPINNER "Initializing PagerSploit..."
/etc/init.d/php8-fpm       stop 2>/dev/null
/etc/init.d/nginx          stop 2>/dev/null
/etc/init.d/bluetoothd     stop 2>/dev/null
/etc/init.d/pineapplepager stop 2>/dev/null
sleep 1

# -- Launch --------------------------------------------------------------------
VIBRATE
"$PYTHON" "$PAYLOAD_DIR/pagersploit.py" \
    --server-ip   "$SERVER_IP" \
    --server-port "$SERVER_PORT" \
    --payload-dir "$PAYLOAD_DIR" \
    > "$LOG_FILE" 2>&1

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    ERROR_DIALOG "PagerSploit exited with error $EXIT_CODE\nCheck $LOG_FILE"
fi
