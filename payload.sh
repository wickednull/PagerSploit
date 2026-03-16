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
LOG "cyan" "Initializing PagerSploit environment..."

# 1. Check for Internet (Skip installation if offline to prevent hanging/crashes)
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
    LOG "green" "Internet detected. Checking for updates..."
    
    # 2. Add Official & Stable Feeds
    if ! grep -q "openwrt_base" /etc/opkg/customfeeds.conf 2>/dev/null; then
        echo "src/gz openwrt_base https://downloads.openwrt.org/releases/23.05.0/packages/mipsel_24kc/base" >> /etc/opkg/customfeeds.conf
        echo "src/gz openwrt_packages https://downloads.openwrt.org/releases/23.05.0/packages/mipsel_24kc/packages" >> /etc/opkg/customfeeds.conf
    fi

    # 3. Fix common library issues (libcap version mismatch)
    [ ! -f /usr/lib/libcap.so.0.8 ] && ln -s /usr/lib/libcap.so.2 /usr/lib/libcap.so.0.8 2>/dev/null

    # 4. Install critical libraries to MMC (Prevents internal memory exhaustion)
    opkg update >/dev/null 2>&1
    opkg install -d mmc libpcap libnl-tiny libstdcpp6 >/dev/null 2>&1

    # 5. Robust installation for problematic tools
    install_to_mmc() {
        local tool=$1
        local pkg=$2
        local url=$3
        if ! command -v "$tool" >/dev/null 2>&1; then
            LOG "yellow" "Installing $tool..."
            # Try feed first
            opkg install -d mmc "$pkg" >/dev/null 2>&1
            # Try direct download if feed failed or is empty
            if ! command -v "$tool" >/dev/null 2>&1 && [ -n "$url" ]; then
                LOG "yellow" "Feed $tool failed. Attempting direct build..."
                wget -q "$url" -O "/tmp/$tool.ipk"
                opkg install -d mmc "/tmp/$tool.ipk" >/dev/null 2>&1
                rm -f "/tmp/$tool.ipk"
            fi
            [ -x "$(command -v $tool)" ] && LOG "green" "Verified $tool" || LOG "red" "$tool skipped"
        fi
    }

    install_to_mmc "nmap" "nmap"
    install_to_mmc "mdk4" "mdk4" "https://github.com/adde88/openwrt-useful-tools/raw/packages-21.02_mkvii/mdk4_4.2-5_mipsel_24kc.ipk"
    install_to_mmc "bully" "bully" "https://github.com/adde88/openwrt-useful-tools/raw/packages-21.02_mkvii/bully_1.4-1_mipsel_24kc.ipk"
    install_to_mmc "reaver" "reaver"
    install_to_mmc "aircrack-ng" "aircrack-ng"
    
    # Python Library
    if ! python3 -c "import sqlite3" >/dev/null 2>&1; then
        LOG "yellow" "Installing sqlite3 library..."
        opkg install -d mmc python3-sqlite3 >/dev/null 2>&1
    fi
else
    LOG "yellow" "Offline Mode: Skipping tool installation."
    LOG "dim" "Connect Pager to internet via USB-C to auto-install tools."
fi

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
