"""Command-line execution entry point for python -m dhcrypt."""

import sys
from dhcrypt.cli import main

if __name__ == "__main__":
    sys.exit(main())
