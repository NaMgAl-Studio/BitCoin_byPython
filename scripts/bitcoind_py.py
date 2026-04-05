#!/usr/bin/env python3
"""
Bitcoin Node Entry Point for PyInstaller Packaging

This script serves as the entry point for building bitcoind-py.exe
"""

import sys
import os
from pathlib import Path

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from bitcoin.node import main

if __name__ == "__main__":
    sys.exit(main())
