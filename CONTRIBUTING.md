# Contributing

Thanks for wanting to help. Bug reports, device detection fixes, new checks, Turkish
wording, documentation: all of it is useful.

## Before you start

- For anything bigger than a small fix, open an issue first so we can agree on the
  approach before you spend time on it.
- Hearthscan is about **home networks** and about explaining things to people who are
  not network experts. Features for scanning other people's networks or the internet
  will not be accepted.

## Setting up

You need [uv](https://docs.astral.sh/uv/). It installs the right Python by itself.

```sh
git clone https://github.com/kalachbeg/Hearthscan.git
cd Hearthscan
uv sync
uv run pytest
uv run hearthscan --help
```

Before you push:

```sh
uv run ruff check
uv run ruff format
uv run pytest
```

CI runs the same on Windows, macOS and Linux with the oldest and newest supported Python.

## Ground rules for the code

- **Probes only look.** A probe may read what a service sends on its own and do the
  handshake needed to see whether it asks for a password. It never logs in, never
  writes or changes anything, and never sends data to printers.
- **Private networks only.** Every code path that connects somewhere goes through the
  scope checks in `scope.py`.
- **Everything from the network is hostile.** Parsers must survive truncated,
  oversized and malicious input without crashing or hanging. Cap what you store.
- **No real data in tests.** Use made-up addresses (192.168.1.x), names and MAC
  suffixes in tests and fixtures. Never commit output from your own network.
- **Few dependencies.** The standard library first. A new dependency needs a good reason.
- **Both languages.** User-facing text lives in `src/hearthscan/i18n/en.json` and
  `tr.json`. If you do not speak Turkish, add the English text to both files and say so
  in the pull request; someone will translate it.

## Adding a check

1. If it needs new information from a service, extend the matching probe in
   `probes.py` and test it against a small fake server in `tests/test_probes.py`.
2. Add the rule to `rules.py` with an id and a severity, and tests in `tests/test_rules.py`.
3. Add `rule.<id>.title`, `.why` and `.fix` to both language files. Write for someone
   who has never heard of the protocol: what it is, what could go wrong at home, and
   what exactly to click or change.

## Device detection

Most detection fixes are a line in `discovery/classify.py` plus a test. The more
specific the clue (an mDNS service, a UPnP device type, a model string), the better.
Vendor names come from the IEEE registry; `scripts/build_oui.py` rebuilds the table.

## How review works

Every pull request is reviewed by a maintainer before it is merged, and nothing goes
into `main` without that approval. CI on pull requests from new contributors starts
after a maintainer has looked at the change. Changes to probes, network code and
GitHub workflows get the most careful review, because people run this tool at home and
trust it with their network.

## Security problems

Please do not open a public issue. See [SECURITY.md](SECURITY.md).

## Code of conduct

Be kind. The short version is in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
