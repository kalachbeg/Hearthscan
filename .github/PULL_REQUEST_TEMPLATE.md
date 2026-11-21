## What does this change?

<!-- A few sentences. Link the issue if there is one: "Fixes #123". -->

## How did you test it?

<!-- Tests you added or ran, and on which OS. A real run on your own network helps too. -->

## Checklist

- [ ] `uv run pytest` and `uv run ruff check` pass
- [ ] Tests and fixtures use made-up data only (no real addresses, MACs or device names)
- [ ] New probes only read what a service volunteers: no logins, no writes, nothing that changes a device
- [ ] Hearthscan still refuses to scan anything outside private networks
- [ ] No new dependency, or the PR explains why it is worth it
- [ ] User-facing text is added to both `en.json` and `tr.json` (ask for help with Turkish if you need it)

Every pull request is reviewed by a maintainer before it is merged. Changes to probes,
network code, the launchers or the release workflow get an extra careful look, since
people run this tool on their home networks.
