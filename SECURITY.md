# Security policy

Hearthscan runs on people's home networks and talks to their devices, so problems in
Hearthscan itself are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private
reporting instead:
[Report a vulnerability](https://github.com/kalachbeg/Hearthscan/security/advisories/new).

Include what you found, how to reproduce it, and what an attacker could do with it. You
will get an answer within a week. Once a fix is out, you are credited in the release
notes unless you prefer not to be.

Examples of what counts:

- A device on the network can crash Hearthscan, make it hang, or run code through a
  crafted reply (mDNS, SSDP, NetBIOS, HTTP and so on).
- Hearthscan can be tricked into connecting to something outside the local network.
- A probe changes something on a device, logs in, or does more than it says.

## Supported versions

Only the latest release gets security fixes. NetShark (1.x) is no longer maintained.

## Using Hearthscan responsibly

Hearthscan only scans private networks and refuses public addresses. Even so, only
scan networks you own or have permission to check.
