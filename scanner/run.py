#!/usr/bin/env python3
"""Entry point used by the plugin commands and hooks (no install step, stdlib only)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcpscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
