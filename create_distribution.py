#!/usr/bin/env python3
"""
Bitcoin Python Distribution Packager

This script creates a ZIP distribution of the entire bitcoin-python project,
including both client and server components.

Usage:
    python create_distribution.py [--output-dir DIR] [--name NAME]

Options:
    --output-dir, -o    Output directory for the ZIP file (default: parent directory)
    --name, -n          Name of the ZIP file (default: bitcoin-python-v0.1.0.zip)
    --exclude-tests     Exclude test files from the distribution
    --clean             Remove __pycache__ directories before packaging

Example:
    python create_distribution.py -o ../releases -n bitcoin-python-latest.zip
"""

import argparse
import os
import shutil
import zipfile
from datetime import datetime
from pathlib import Path
from typing import List, Set


# Configuration
PROJECT_NAME = "bitcoin-python"
PROJECT_VERSION = "0.1.0"
DEFAULT_OUTPUT_NAME = f"{PROJECT_NAME}-v{PROJECT_VERSION}.zip"

# Directories and files to exclude
DEFAULT_EXCLUDES = {
    # Build artifacts
    "__pycache__",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    ".Python",
    
    # Distribution/build directories
    "build",
    "dist",
    "*.egg-info",
    "*.egg",
    
    # IDE and editor files
    ".vscode",
    ".idea",
    "*.swp",
    "*.swo",
    "*~",
    
    # Version control
    ".git",
    ".gitignore",
    ".gitattributes",
    
    # Virtual environments
    "venv",
    ".venv",
    "env",
    ".env",
    
    # Test caches
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".coverage",
    "htmlcov",
    
    # Other
    "*.log",
    "*.tmp",
}

TEST_EXCLUDES = {
    "tests",
    "test",
    "*.test.py",
    "test_*.py",
}


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.absolute()


def should_exclude(path: Path, excludes: Set[str]) -> bool:
    """Check if a path should be excluded."""
    name = path.name
    
    for pattern in excludes:
        if pattern.startswith("*."):
            # Wildcard extension pattern
            if name.endswith(pattern[1:]):
                return True
        elif "*" in pattern:
            # Simple wildcard
            import fnmatch
            if fnmatch.fnmatch(name, pattern):
                return True
        else:
            # Exact match
            if name == pattern:
                return True
    
    return False


def clean_pycache(root: Path):
    """Remove all __pycache__ directories."""
    count = 0
    for pycache in root.rglob("__pycache__"):
        try:
            shutil.rmtree(pycache)
            count += 1
            print(f"  Removed: {pycache.relative_to(root)}")
        except Exception as e:
            print(f"  Warning: Could not remove {pycache}: {e}")
    
    return count


def create_zip(
    source_dir: Path,
    output_path: Path,
    excludes: Set[str],
    verbose: bool = True
) -> dict:
    """Create a ZIP file of the source directory."""
    
    stats = {
        "files_added": 0,
        "dirs_skipped": 0,
        "files_skipped": 0,
        "total_size": 0,
    }
    
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for item in source_dir.rglob("*"):
            # Skip excluded items
            if should_exclude(item, excludes):
                if item.is_dir():
                    stats["dirs_skipped"] += 1
                else:
                    stats["files_skipped"] += 1
                continue
            
            if item.is_file():
                # Calculate archive path (relative to source)
                arcname = item.relative_to(source_dir)
                
                # Add file to ZIP
                zf.write(item, arcname)
                
                stats["files_added"] += 1
                stats["total_size"] += item.stat().st_size
                
                if verbose and stats["files_added"] % 100 == 0:
                    print(f"  Added {stats['files_added']} files...")
    
    return stats


def create_readme(source_dir: Path) -> Path:
    """Create a distribution README file."""
    
    readme_content = f'''# Bitcoin Core Python Implementation v{PROJECT_VERSION}

## Distribution Contents

This ZIP file contains the complete Bitcoin Python implementation, including:

### Client Components
- **bitcoin-cli-py**: Command-line interface for Bitcoin RPC
- **bitcoin-wallet-py**: Wallet management tool

### Server Components  
- **bitcoind-py**: Bitcoin node server implementation
- **RPC Server**: JSON-RPC HTTP server

### Directory Structure

```
bitcoin-python/
├── src/bitcoin/           # Main source code
│   ├── chain/             # Blockchain management
│   ├── consensus/         # Consensus rules
│   ├── crypto/            # Cryptographic functions
│   ├── mempool/           # Memory pool
│   ├── p2p/               # Peer-to-peer networking
│   ├── primitives/        # Basic data structures
│   ├── rpc/               # RPC server/client
│   ├── script/            # Bitcoin script interpreter
│   ├── util/              # Utilities
│   └── wallet/            # Wallet implementation
├── scripts/               # Entry point scripts
│   ├── bitcoind_py.py     # Node server entry
│   ├── bitcoin_cli_py.py  # CLI entry
│   ├── bitcoin_wallet_py.py # Wallet entry
│   └── run_rpc_server.py  # RPC server launcher
├── tests/                 # Unit tests
├── build_exe.py           # EXE builder script
├── pyproject.toml         # Project configuration
└── README.md              # Project documentation
```

## Quick Start

### Installation

1. Extract this ZIP file to your desired location
2. Install Python 3.11 or later
3. Install dependencies:

```bash
cd bitcoin-python
pip install -e .
```

### Running the RPC Server

```bash
python scripts/run_rpc_server.py --host 127.0.0.1 --port 8332 --user bitcoin --password yourpassword
```

### Using the CLI

```bash
# Get blockchain info
python -m bitcoin.cli getblockchaininfo

# Get wallet balance
python -m bitcoin.cli getbalance

# Generate new address
python -m bitcoin.cli getnewaddress
```

## Building Executables

To create standalone .exe files:

```bash
pip install pyinstaller
python build_exe.py --all --clean
```

The executables will be created in the `dist/` directory.

## Requirements

- Python >= 3.11
- coincurve >= 19.0.0
- cryptography >= 42.0.0
- pydantic >= 2.5.0
- fastapi >= 0.109.0
- uvicorn >= 0.27.0
- aiohttp >= 3.9.0

## License

MIT License

## Links

- Original Bitcoin Core: https://github.com/bitcoin/bitcoin
- Documentation: See README.md in the project root

---
Created: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
'''
    
    readme_path = source_dir / "DISTRIBUTION_README.txt"
    readme_path.write_text(readme_content)
    return readme_path


def main():
    parser = argparse.ArgumentParser(
        description=f"Create ZIP distribution of {PROJECT_NAME}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python create_distribution.py
    python create_distribution.py -o ../releases -n bitcoin-python-latest.zip
    python create_distribution.py --exclude-tests --clean
        """
    )
    
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default=None,
        help="Output directory for the ZIP file"
    )
    
    parser.add_argument(
        "--name", "-n",
        type=str,
        default=DEFAULT_OUTPUT_NAME,
        help=f"Name of the ZIP file (default: {DEFAULT_OUTPUT_NAME})"
    )
    
    parser.add_argument(
        "--exclude-tests",
        action="store_true",
        help="Exclude test files from the distribution"
    )
    
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove __pycache__ directories before packaging"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=True,
        help="Show detailed output"
    )
    
    args = parser.parse_args()
    
    # Get paths
    source_dir = get_project_root()
    
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        output_dir = source_dir.parent
    
    output_path = output_dir / args.name
    
    print(f"\n{'='*60}")
    print(f"Bitcoin Python Distribution Packager")
    print(f"{'='*60}\n")
    
    print(f"Source: {source_dir}")
    print(f"Output: {output_path}")
    
    # Clean if requested
    if args.clean:
        print(f"\nCleaning __pycache__ directories...")
        count = clean_pycache(source_dir)
        print(f"Cleaned {count} directories")
    
    # Build exclude set
    excludes = DEFAULT_EXCLUDES.copy()
    if args.exclude_tests:
        excludes.update(TEST_EXCLUDES)
    
    # Create distribution README
    print(f"\nCreating distribution README...")
    readme_path = create_readme(source_dir)
    print(f"Created: {readme_path.name}")
    
    # Create ZIP
    print(f"\nCreating ZIP archive...")
    stats = create_zip(source_dir, output_path, excludes, args.verbose)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Packaging Complete")
    print(f"{'='*60}")
    print(f"Files added:    {stats['files_added']}")
    print(f"Files skipped:  {stats['files_skipped']}")
    print(f"Dirs skipped:   {stats['dirs_skipped']}")
    print(f"Total size:     {stats['total_size'] / (1024*1024):.2f} MB")
    print(f"ZIP size:       {output_path.stat().st_size / (1024*1024):.2f} MB")
    print(f"Output:         {output_path}")
    
    # Clean up the temporary README
    readme_path.unlink()
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
