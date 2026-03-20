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
export CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1
if [ -d "/mmc/root/payloads/user/reconnaissance/pager_bjorn/lib/nmap/scripts" ]; then
    export NMAPDIR="/mmc/root/payloads/user/reconnaissance/pager_bjorn/lib/nmap"
elif [ -d "/mmc/usr/share/nmap/scripts" ]; then export NMAPDIR="/mmc/usr/share/nmap"
fi
export CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1
if [ -d "/mmc/root/payloads/user/reconnaissance/pager_bjorn/lib/nmap/scripts" ]; then
    export NMAPDIR="/mmc/root/payloads/user/reconnaissance/pager_bjorn/lib/nmap"
elif [ -d "/mmc/usr/share/nmap/scripts" ]; then
    export NMAPDIR="/mmc/usr/share/nmap"
fi
export CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1
# NMAPDIR: ensure nmap finds its scripts (Loki pattern)
if [ -d "/mmc/root/payloads/user/reconnaissance/pager_bjorn/lib/nmap/scripts" ]; then
    export NMAPDIR="/mmc/root/payloads/user/reconnaissance/pager_bjorn/lib/nmap"
elif [ -d "/mmc/usr/share/nmap/scripts" ]; then
    export NMAPDIR="/mmc/usr/share/nmap"
fi

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

_btn_wait() {
    local empty=0 tries=0
    while [ $tries -lt 120 ]; do
        BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
        case "$BUTTON" in
            GREEN|A|BTN_A|BUTTON_A|16|0x10) return 0 ;;
            RED|B|BTN_B|BUTTON_B|32|0x20)   return 1 ;;
        esac
        if [ -z "$BUTTON" ]; then
            empty=$((empty+1))
            [ $empty -ge 3 ] && { LOG "yellow" "(auto-starting — button unavailable)"; return 0; }
            sleep 0.5
        else
            empty=0
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

# -- Stop services -------------------------------------------------------------
SPINNER_ID=$(START_SPINNER "Initializing PagerSploit...")
# Stop pineapplepager (display manager) to avoid screen conflict
# but leave pineapd running so recon.db stays populated with tri-band data
/etc/init.d/php8-fpm       stop 2>/dev/null
/etc/init.d/nginx          stop 2>/dev/null
/etc/init.d/bluetoothd     stop 2>/dev/null
/etc/init.d/pineapplepager stop 2>/dev/null
# pineapd keeps running — it owns recon.db and the radio hopping
sleep 1
sleep 0.5
STOP_SPINNER "$SPINNER_ID" 2>/dev/null

# -- Network check (Loki pattern) ---------------------------------------------
HAS_NETWORK=false
for _ip in $(ip -4 addr 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1); do
    if [ "$_ip" != "127.0.0.1" ]; then
        HAS_NETWORK=true
        break
    fi
done
if [ "$HAS_NETWORK" = false ]; then
    LOG "yellow" "No network interface active — LAN modules will be limited"
fi

# -- Network check (Loki pattern) ---------------------------------------------
HAS_NETWORK=false
for _ip in $(ip -4 addr 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1); do
    if [ "$_ip" != "127.0.0.1" ]; then HAS_NETWORK=true; break; fi
done
[ "$HAS_NETWORK" = false ] && LOG "yellow" "No network active — LAN modules limited"

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

# -- Cleanup (Loki pattern) ----------------------------------------------------
killall nmap 2>/dev/null
killall aircrack-ng 2>/dev/null

# -- Cleanup (Loki pattern) ----------------------------------------------------
killall nmap 2>/dev/null; killall aircrack-ng 2>/dev/null

# -- Restore services ----------------------------------------------------------
/etc/init.d/bluetoothd     start 2>/dev/null &
/etc/init.d/nginx          start 2>/dev/null &
/etc/init.d/php8-fpm       start 2>/dev/null &
/etc/init.d/pineapplepager start 2>/dev/null &
