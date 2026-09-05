"""Entry point for `python -m quantumready`."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
