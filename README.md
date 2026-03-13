# PagerSploit

A wireless penetration testing framework for the [Hak5 WiFi Pineapple](https://hak5.org/products/wifi-pineapple). Modules run on the Pineapple — you control everything from a browser on your phone or laptop over USB-C ethernet.

**Built by [wickedNull](https://github.com/wickednull)**

---

## How It Works

PagerSploit runs a web UI on `http://172.16.52.1:8080` — the Pineapple's always-up management bridge. Connect via USB-C ethernet, open your browser, and you have a full pentest dashboard. No need to SSH in to run attacks.

The Pager display shows live module status so you know what's running at a glance without looking at your phone.

```
Operator (phone/laptop)
        │
    USB-C ethernet
        │
  172.16.52.1:8080  ◄── Browser UI
  WiFi Pineapple
        │
  wlan0 / wlan0mon / wlan1mon
        │
     Target network
```

---

## Install

```bash
cd /root/payloads/user/interception
git clone https://github.com/wickednull/PagerSploit
chmod +x PagerSploit/payload.sh
```

Run it from the Pager UI under **Interception → PagerSploit**, or:

```bash
bash /root/payloads/user/interception/PagerSploit/payload.sh
```

Then open `http://172.16.52.1:8080` in your browser.

---

## Modules

### WiFi

| Module | Description |
|--------|-------------|
| **AP Scanner** | Scan for nearby access points, display SSID / BSSID / channel / signal / encryption |
| **Deauth** | Deauthenticate clients from a target AP (`wlan1mon`, continuous or fixed count) |
| **Handshake Capture** | Put `wlan0mon` on target channel, capture WPA handshake, auto-detect with aircrack-ng |
| **WPA Crack** | Run aircrack-ng against a captured `.cap` file with a wordlist |
| **Evil Twin** | Clone a target SSID on `br-evil` (10.0.0.1), optionally serve a captive portal |
| **Karma Attack** | Respond to all probe requests with a matching SSID via airbase-ng |
| **Beacon Flood** | Flood beacon frames with a list of SSIDs |
| **Probe Harvest** | Passive collection of probe requests — reveals SSIDs devices are looking for |
| **Auth Flood** | Flood authentication frames at a target AP |
| **WPS Scan** | Scan for WPS-enabled APs and report WPS version / locked status |

### LAN

| Module | Description |
|--------|-------------|
| **ARP Scan** | Discover live hosts on a subnet |
| **Port Scan** | nmap TCP scan against a target host |
| **Default Cred Spray** | Try common default credentials against SSH, FTP, HTTP, Telnet |
| **mDNS Discovery** | Passive mDNS listener — finds printers, cameras, IoT devices |
| **DNS Spoof** | Redirect a domain to an IP via dnsmasq |
| **HTTP Intercept** | Capture plaintext HTTP traffic on an interface |

---

## Captive Portals (Evil Twin)

Drop any `.html` file into the `portals/` directory and it will appear as an option in the Evil Twin module. The file is served as a captive portal to clients who connect to the cloned AP.

Compatible with Flipper Zero portal HTML files.

```
PagerSploit/
└── portals/
    ├── hotel_wifi.html
    ├── coffee_shop.html
    └── your_portal.html
```

---

## Loot

All captured data is saved to `PagerSploit/loot/`:

```
loot/
├── handshakes/     # .cap files from handshake capture
├── credentials/    # HTTP intercept and default cred spray results
├── scans/          # ARP, port scan, mDNS, probe harvest output
└── pmkid/          # PMKID captures
```

The browser UI has a **Loot Manager** tab with download links for all captured files.

Wordlists go in `PagerSploit/wordlists/` and will appear in the WPA Crack module.

---

## Requirements

- WiFi Pineapple (Pager)
- aircrack-ng suite in `/mmc/usr/sbin/` (pre-installed on Pineapple)
- nmap at `/mmc/root/payloads/user/reconnaissance/pager_bjorn/lib/nmap`
- Python 3 at `/mmc/usr/bin/python3`
- nftables (`nft`)

---

## Notes

- Deauth uses `wlan1mon` (5GHz monitor) by default to leave `wlan0mon` free for capture
- The web UI polls every 2 seconds for live status updates
- `br-evil` (10.0.0.1) is the dedicated evil AP bridge — already configured by the Pineapple
- Stopping a module from the UI cleanly kills background processes and tears down nftables rules
