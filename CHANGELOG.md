# Changelog

Notable changes to this project. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

Hearthscan is a rewrite of NetShark with a narrower goal: checking the network
in your own home.

### Added

- Async TCP connect scanner that tells closed ports (the host sends a reset)
  apart from filtered ones (no answer at all). Ports that look filtered get a
  second try on hosts that answered elsewhere, since a single lost SYN is common
  on Wi-Fi. IPv4 and IPv6, including link-local addresses with a zone.
- On Windows the scanner turns off SYN retransmission on its sockets, so a
  refused port shows up as closed right away instead of after the two seconds
  or so Windows normally spends retrying.
- Scope checks: targets have to be on a private, link-local or loopback network.
- Detection of the local interface and default gateway on Windows, macOS and
  Linux, skipping VPN, VM and container adapters. Running inside WSL 2 or a
  container prints a note, since that network usually isn't the home LAN.
- Ctrl+C stops a scan cleanly.
- Device discovery without admin rights: a NetBIOS status sweep fills the OS
  neighbor table, which is then read on every platform (GetIpNetTable2 on
  Windows, `ip neigh` or /proc/net/arp on Linux, `arp -an` on macOS). mDNS,
  SSDP/UPnP and reverse DNS run alongside it for names and models.
- MAC vendor lookup from the IEEE registries (MA-L, MA-M and MA-S), shipped as
  a small compressed table. `scripts/build_oui.py` rebuilds it.
- A first guess at what each device is: router, computer, phone, printer,
  camera, TV, speaker, NAS, console or smart home gadget, with the reasons.
- `hearthscan devices` lists what is on the network.
- Light service probes for open ports: banners, web page titles and login
  pages, and handshakes that show whether Redis, MQTT, VNC, RTSP cameras, ADB,
  SOCKS, Docker or Elasticsearch let anyone in without a password, and whether
  SMB still speaks version 1. Nothing is ever logged into, and printers are
  left alone.
- 30 checks with a severity each, from an open Telnet port to a camera stream
  anyone on the network can watch, and a score out of 100 for the household.
- Every finding explains what it means and what to do about it, in English and
  Turkish. The language follows the system and can be overridden with
  `HEARTHSCAN_LANG`.
- Results can be saved as JSON and read back.
- A terminal interface built on rich: a start menu when Hearthscan runs without
  a command, a score panel, a table of devices and every finding with what to
  do about it, in English or Turkish (`--lang en` or `--lang tr`).
- `hearthscan scan` takes `--ports`, `--timeout`, `--no-probe`, `--json` and
  `--output`, and `--fail-on high` makes it exit with status 3 when something
  that serious turns up, for use in scripts.
- `hearthscan devices --json` and `hearthscan net --json`.
- Router checks over UPnP: the internet address, the connection type and every
  port the router forwards from the internet, with a warning when one leads to
  a risky service such as Telnet, Remote Desktop or a camera stream. Double NAT
  and carrier-grade NAT are pointed out too. These checks only ask the router
  for information; they never change anything on it. `hearthscan router` shows
  them on their own.
- Reports: `hearthscan scan -o report.html` writes a single HTML file with the
  score, every finding and the device list, readable on a phone and printable,
  with no scripts and nothing loaded from the internet. `hearthscan report`
  turns a saved JSON result into one later.
- `hearthscan diff old.json new.json` shows what changed between two scans:
  devices that came or went, risks that are new and risks that were fixed.
- Watch mode: `hearthscan watch` looks at the network every few minutes and
  tells you when a device turns up that it has never seen before. The devices
  it knows are kept in a small file in your user folder, and
  `hearthscan known` lists them.
- A desktop window: `hearthscan gui`, or option 2 in the menu, shows the same
  check with a big start button, live progress, the results as cards, the
  router and a searchable device list, in English or Turkish. It runs in a
  pywebview window when the `window` extra is installed and in your browser
  otherwise. The page is served on 127.0.0.1 only, behind a random token, and
  loads nothing from the internet.
- The start menu is now: check my network, open the window, watch, devices,
  router, network details.

### Removed

- Subdomain enumeration, the website header/TLS check and the netstat based
  "monitor" from NetShark. Plenty of good tools already cover those.

## [1.0.0] - 2025-12-18

Published as NetShark, a general purpose port, subdomain and web scanner.
