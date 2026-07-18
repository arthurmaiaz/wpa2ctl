# wpa2ctl

A CLI tool that orchestrates the full WPA2 auditing workflow — network scanning, handshake capture, and password strength testing — automating the manual process normally done with `airodump-ng`, `aircrack-ng`, and `hashcat`.

> ⚠️ **Strictly for educational use in authorized environments.** See [legal_notice.md](legal_notice.md) before using.

## Overview

`wpa2ctl` takes the manual WPA2 auditing process (which normally requires running several separate commands and manually watching the output) and turns it into an automated pipeline with event detection, structured logging, and a final report.

```
Network scan → Target selection + authorization confirmation → Handshake capture
      → Format conversion → Password testing (wordlist) → Report
```

## Features

- [ ] Automatic monitor mode management (`airmon-ng`)
- [ ] Nearby network scan with a formatted table (BSSID, channel, signal, encryption)
- [ ] Explicit authorization confirmation before any capture
- [ ] Handshake capture with automatic success detection
- [ ] Format conversion for hashcat (`.hc22000`)
- [ ] Password testing via `aircrack-ng` or `hashcat`, with real-time progress
- [ ] Final JSON/HTML report with process metrics
- [ ] Automatic cleanup (disables monitor mode, removes temp files)

## Requirements

- Kali Linux (or a distro with the `aircrack-ng` suite)
- WiFi adapter with monitor mode and packet injection support
- Python 3.10+
- `hashcat` (optional, recommended for GPU acceleration)
- A wordlist (e.g. `rockyou.txt`) — **not included in this repository**

## Installation

```bash
git clone https://github.com/your-username/wpa2ctl.git
cd wpa2ctl
pip install -r requirements.txt
```

## Usage

```bash
sudo python src/main.py --interface wlan0 --scan-time 20 --wordlist ~/wordlists/rockyou.txt --output report.json
```

## Project structure

```
wpa2ctl/
├── src/
│   ├── interface.py   # manages monitor mode
│   ├── scanner.py      # scans available networks
│   ├── capture.py      # handshake capture
│   ├── cracker.py       # password testing via wordlist
│   ├── report.py         # report generation
│   └── main.py            # main CLI
├── wordlists/               # (not versioned)
├── docs/
├── legal_notice.md
└── requirements.txt
```

## Status

🚧 Work in progress — a personal cybersecurity study project.

## License and ethical use

This project exists for educational purposes and personal lab practice. See [legal_notice.md](legal_notice.md) before using.
