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

# -- Dependencies --------------------------------------------------------------
LOG "cyan" "Checking dependencies..."

# Function to check and install
check_dep() {
    local tool=$1
    local pkg=$2
    if ! command -v "$tool" >/dev/null 2>&1; then
        LOG "yellow" "Missing $tool. Installing $pkg..."
        opkg update >/dev/null 2>&1
        opkg install "$pkg" >/dev/null 2>&1
        if ! command -v "$tool" >/dev/null 2>&1; then
            LOG "red" "Failed to install $pkg. Some modules may not work."
        else
            LOG "green" "Installed $pkg"
        fi
    fi
}

# Special check for python packages
check_py_pkg() {
    local pkg=$1
    if ! python3 -c "import $pkg" >/dev/null 2>&1; then
        LOG "yellow" "Missing python library $pkg. Installing..."
        opkg update >/dev/null 2>&1
        opkg install "python3-$pkg" >/dev/null 2>&1
    fi
}

# Add community repo for advanced tools
if ! grep -q "adde88" /etc/opkg/customfeeds.conf 2>/dev/null; then
    echo "src/gz adde88_tools https://raw.githubusercontent.com/adde88/openwrt-useful-tools/master/packages/mkvii" >> /etc/opkg/customfeeds.conf
    LOG "cyan" "Added adde88 community repository"
fi

# Install core tools
check_dep "nmap" "nmap"
check_dep "mdk4" "mdk4"
check_dep "reaver" "reaver"
check_dep "bully" "bully"
check_dep "pixiewps" "pixiewps"
check_dep "aircrack-ng" "aircrack-ng"
check_dep "hcitool" "bluez-utils"
check_py_pkg "sqlite3"

# -- Stop services -------------------------------------------------------------
SPINNER_ID=$(START_SPINNER "Initializing PagerSploit...")
# Stop pineapplepager (display manager) to avoid screen conflict
# but leave pineapd running so recon.db stays populated with tri-band data
/etc/init.d/pineapplepager stop 2>/dev/null
# pineapd keeps running — it owns recon.db and the radio hopping
sleep 1
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
/etc/init.d/pineapplepager start 2>/dev/null &
