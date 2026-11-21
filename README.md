# Hearthscan

Hearthscan looks at the network in your home and tells you, in plain words, what is
on it and what those devices expose.

This is the 2.0 rewrite of the project that used to be called NetShark. It is not
finished yet: everything works from the terminal, including reports and watch mode;
the desktop window and the one-line launchers come next.

Hearthscan only scans private networks (192.168.x.x, 10.x.x.x, 172.16-31.x.x and
link-local addresses). Public addresses are refused.

## Working on it

```sh
uv sync
uv run pytest
uv run hearthscan                 # menu
uv run hearthscan scan
uv run hearthscan scan --lang tr
uv run hearthscan scan -o report.html
uv run hearthscan scan --json -o scan.json
uv run hearthscan report scan.json
uv run hearthscan diff last-week.json scan.json
uv run hearthscan watch
uv run hearthscan known
uv run hearthscan devices
uv run hearthscan router
uv run hearthscan net
uv run hearthscan ports 192.168.1.1 -p 22,80,443
```

## Contributing

Bug reports, ideas and pull requests are welcome. Start with
[CONTRIBUTING.md](CONTRIBUTING.md). Security problems go through
[SECURITY.md](SECURITY.md), not the issue tracker.

## Star history

<a href="https://star-history.com/#kalachbeg/hearthscan&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=kalachbeg/hearthscan&type=Date&theme=dark" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=kalachbeg/hearthscan&type=Date" />
    <img alt="Star history of Hearthscan" src="https://api.star-history.com/svg?repos=kalachbeg/hearthscan&type=Date" />
  </picture>
</a>
