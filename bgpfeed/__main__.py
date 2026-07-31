"""Запуск через `python3 -m bgpfeed`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
