# Hearthscan

Hearthscan looks at the network in your home and tells you, in plain words, what is
on it and what those devices expose.

This is the 2.0 rewrite of the project that used to be called NetShark. It is not
usable yet: the scanner core is in, device discovery and the actual checks come next.

Hearthscan only scans private networks (192.168.x.x, 10.x.x.x, 172.16-31.x.x and
link-local addresses). Public addresses are refused.

## Working on it

```sh
uv sync
uv run pytest
uv run hearthscan net
uv run hearthscan ports 192.168.1.1
```
