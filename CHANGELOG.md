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

### Removed

- Subdomain enumeration, the website header/TLS check and the netstat based
  "monitor" from NetShark. Plenty of good tools already cover those.

## [1.0.0] - 2025-12-18

Published as NetShark, a general purpose port, subdomain and web scanner.
