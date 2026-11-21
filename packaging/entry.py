# The script PyInstaller freezes (see hearthscan.spec). It does what
# `python -m hearthscan` does.
from hearthscan.cli import main

raise SystemExit(main())
