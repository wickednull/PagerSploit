# PagerSploit

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-WiFi%20Pineapple%20Pager-orange)
![Status](https://img.shields.io/badge/Status-Active-green)
![License](https://img.shields.io/badge/License-Research-lightgrey)

PagerSploit is a **browser‑controlled wireless penetration testing
framework** designed specifically for the **Hak5 WiFi Pineapple Pager**.

It runs a lightweight Python backend and exposes a web control panel
that can be accessed directly from a phone or laptop over **USB‑C
Ethernet**. This allows operators to control wireless attacks, monitor
results, and manage captured data without SSH access.

PagerSploit also integrates with the **Pager hardware screen**,
displaying module status and activity directly on the device.

------------------------------------------------------------------------

# Dashboard

Access the interface at:

http://172.16.52.1:8080

The dashboard provides real‑time control of all attack modules.

## Example UI

Add screenshots here once available:

    docs/screenshots/dashboard.png
    docs/screenshots/wifi_scan.png
    docs/screenshots/loot_manager.png

------------------------------------------------------------------------

# Architecture

    Operator Device (Phone / Laptop)
                │
            USB‑C Ethernet
                │
         172.16.52.1:8080
         PagerSploit Web UI
                │
          Python Backend
                │
      WiFi Pineapple Pager
                │
     wlan0 / wlan0mon / wlan1mon
                │
            Target Network

The Python backend launches modules as **background jobs**, manages
logs, and saves captured data to structured directories.

------------------------------------------------------------------------

# Features

## Web Based Control

-   Browser controlled attack interface
-   Real‑time module status
-   No SSH required for normal operation
-   Works from mobile devices

## Pager Hardware Integration

-   Displays module status on the Pineapple Pager screen
-   Uses `pagerctl` when available
-   Fully functional even without hardware display

## Job & Process Management

-   Modules run as background tasks
-   Clean stop signals
-   Automatic logging
-   Persistent attack sessions

## Loot Management

Captured data is automatically organized:

    loot/
    ├── handshakes/
    ├── credentials/
    ├── scans/
    └── pmkid/

The **Loot Manager** in the web UI allows files to be downloaded
directly.

------------------------------------------------------------------------

# Modules

## WiFi Modules

  Module              Description
  ------------------- -----------------------------------------------
  AP Scanner          Detects nearby access points
  Deauth              Disconnects clients from a target AP
  Handshake Capture   Captures WPA handshakes
  WPA Crack           Uses aircrack-ng to attempt password recovery
  Evil Twin           Creates rogue access point
  Karma Attack        Responds to probe requests
  Beacon Flood        Broadcasts fake SSIDs
  Probe Harvest       Collects probe request data
  Auth Flood          Sends large authentication bursts
  WPS Scan            Detects WPS enabled routers

------------------------------------------------------------------------

## LAN Modules

  Module                     Description
  -------------------------- ---------------------------------
  ARP Scan                   Discovers devices on network
  Port Scan                  Runs TCP scans using nmap
  Default Credential Spray   Attempts common credentials
  mDNS Discovery             Finds IoT devices
  DNS Spoof                  Redirects domains using dnsmasq
  HTTP Intercept             Captures plaintext HTTP traffic

------------------------------------------------------------------------

# Captive Portals

Custom portals can be placed inside:

    PagerSploit/portals/

Example:

    portals/
    ├── hotel_wifi.html
    ├── coffee_shop.html
    └── custom_portal.html

These portals will automatically appear in the **Evil Twin module**.

------------------------------------------------------------------------

# Installation

Clone into the Pineapple payload directory:

``` bash
cd /root/payloads/user/interception
git clone https://github.com/wickednull/PagerSploit
chmod +x PagerSploit/payload.sh
```

Launch from the Pineapple UI:

    Interception → PagerSploit

Or start manually:

``` bash
bash /root/payloads/user/interception/PagerSploit/payload.sh
```

Then open:

    http://172.16.52.1:8080

------------------------------------------------------------------------

# Requirements

Expected environment:

-   WiFi Pineapple Pager
-   Python 3
-   aircrack-ng
-   nmap
-   dnsmasq
-   nftables

Expected paths:

    /mmc/usr/sbin/
    /mmc/usr/bin/python3
    /mmc/root/payloads/

------------------------------------------------------------------------

# Credits

**wickedNull**  
Creator and lead developer
https://github.com/wickednull

**sinXne0**  
Development support, testing, and collaboration  
https://github.com/sinXne0

**BrainPhreak**  
Creator of `pagerctl` used for Pager hardware display integration  
https://github.com/pineapple-pager-projects
------------------------------------------------------------------------

# Disclaimer

PagerSploit is intended for **authorized penetration testing and
security research only**.

Unauthorized use against networks you do not own or have permission to
test may violate laws.

Use responsibly.

------------------------------------------------------------------------

# License

See repository license.
