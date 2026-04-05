#!/usr/bin/env python3
"""
Bitcoin Wallet CLI Entry Point for PyInstaller Packaging

This script serves as the entry point for building bitcoin-wallet-py.exe
"""

import sys
import os
from pathlib import Path

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from bitcoin.wallet.cli import main

if __name__ == "__main__":
    sys.exit(main())
