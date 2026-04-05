#!/usr/bin/env python3
"""
Bitcoin Python EXE Builder

This script packages Python scripts into standalone executable files (.exe) using PyInstaller.
It creates executables for:
  - bitcoind-py.exe    : Bitcoin node server
  - bitcoin-cli-py.exe : Command-line client
  - bitcoin-wallet-py.exe : Wallet tool

Usage:
    python build_exe.py [--onefile] [--console] [--clean]

Requirements:
    pip install pyinstaller

Options:
    --onefile    : Create a single executable file (larger but portable)
    --console    : Show console window (default for CLI tools)
    --clean      : Clean build artifacts before building
    --all        : Build all executables
    --node       : Build only bitcoind-py.exe
    --cli        : Build only bitcoin-cli-py.exe
    --wallet     : Build only bitcoin-wallet-py.exe

Reference: Bitcoin Core build system
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


# Configuration
PROJECT_NAME = "Bitcoin Core Python"
PROJECT_VERSION = "0.1.0"

# Entry points defined in pyproject.toml
ENTRY_POINTS = {
    "bitcoind-py": {
        "script": "scripts/bitcoind_py.py",
        "description": "Bitcoin Node Server",
        "console": True,
        "icon": None,  # Can add .ico path here
    },
    "bitcoin-cli-py": {
        "script": "scripts/bitcoin_cli_py.py", 
        "description": "Bitcoin CLI Client",
        "console": True,
        "icon": None,
    },
    "bitcoin-wallet-py": {
        "script": "scripts/bitcoin_wallet_py.py",
        "description": "Bitcoin Wallet Tool",
        "console": True,
        "icon": None,
    },
}


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.absolute()


def get_src_path() -> Path:
    """Get the src directory path."""
    return get_project_root() / "src"


def clean_build_artifacts():
    """Clean build and dist directories."""
    project_root = get_project_root()
    
    dirs_to_clean = ["build", "dist", "__pycache__"]
    files_to_clean = ["*.spec"]
    
    for dir_name in dirs_to_clean:
        dir_path = project_root / dir_name
        if dir_path.exists():
            print(f"Cleaning {dir_path}...")
            shutil.rmtree(dir_path)
    
    # Clean .spec files
    for spec_file in project_root.glob("*.spec"):
        print(f"Cleaning {spec_file}...")
        spec_file.unlink()
    
    # Clean __pycache__ in src
    for pycache in get_src_path().rglob("__pycache__"):
        print(f"Cleaning {pycache}...")
        shutil.rmtree(pycache)


def build_pyinstaller_command(
    name: str,
    entry: dict,
    onefile: bool = True,
    console: bool = True,
    output_dir: Optional[Path] = None
) -> List[str]:
    """Build PyInstaller command for an entry point."""
    
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", name,
        "--noconfirm",  # Overwrite output
    ]
    
    # Single file or directory
    if onefile:
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")
    
    # Console or windowed
    if console:
        cmd.append("--console")
    else:
        cmd.append("--windowed")
    
    # Add hidden imports for common dependencies
    hidden_imports = [
        "coincurve",
        "cryptography",
        "pydantic",
        "fastapi",
        "uvicorn",
        "aiohttp",
        "plyvel",
        "asyncio_pool",
        "pyzmq",
        "json",
        "asyncio",
        "logging",
        "argparse",
        "pathlib",
        "typing",
        "dataclasses",
        "hashlib",
        "hmac",
        "secrets",
        "time",
        "datetime",
        "struct",
        "io",
        "os",
        "sys",
    ]
    
    for imp in hidden_imports:
        cmd.extend(["--hidden-import", imp])
    
    # Add src path
    src_path = get_src_path()
    cmd.extend(["--paths", str(src_path)])
    
    # Add icon if specified
    if entry.get("icon"):
        cmd.extend(["--icon", entry["icon"]])
    
    # Add collect all for key packages
    collect_packages = ["bitcoin", "coincurve", "cryptography", "pydantic"]
    for pkg in collect_packages:
        cmd.extend(["--collect-all", pkg])
    
    # Output directory
    if output_dir:
        cmd.extend(["--distpath", str(output_dir)])
    
    # Entry point script
    script_path = get_project_root() / entry["script"]
    cmd.append(str(script_path))
    
    return cmd


def build_executable(
    name: str,
    entry: dict,
    onefile: bool = True,
    console: bool = True,
    output_dir: Optional[Path] = None
) -> bool:
    """Build a single executable."""
    
    print(f"\n{'='*60}")
    print(f"Building: {name}")
    print(f"Description: {entry['description']}")
    print(f"{'='*60}\n")
    
    cmd = build_pyinstaller_command(name, entry, onefile, console, output_dir)
    
    print(f"Running: {' '.join(cmd[:5])}...")
    
    try:
        result = subprocess.run(
            cmd,
            cwd=get_project_root(),
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"Error building {name}:")
            print(result.stderr)
            return False
        
        print(f"Successfully built {name}")
        
        # Check if exe was created
        if output_dir:
            exe_path = output_dir / name
            if sys.platform == "win32":
                exe_path = output_dir / f"{name}.exe"
        else:
            exe_path = get_project_root() / "dist" / name
            if sys.platform == "win32":
                exe_path = get_project_root() / "dist" / f"{name}.exe"
        
        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print(f"Output: {exe_path} ({size_mb:.2f} MB)")
        
        return True
        
    except Exception as e:
        print(f"Exception building {name}: {e}")
        return False


def build_all(onefile: bool = True, console: bool = True, output_dir: Optional[Path] = None):
    """Build all executables."""
    
    print(f"\n{'#'*60}")
    print(f"# {PROJECT_NAME} v{PROJECT_VERSION}")
    print(f"# Building all executables")
    print(f"# Mode: {'onefile' if onefile else 'onedir'}, {'console' if console else 'windowed'}")
    print(f"{'#'*60}\n")
    
    success_count = 0
    failed = []
    
    for name, entry in ENTRY_POINTS.items():
        use_console = console if entry["console"] else False
        
        if build_executable(name, entry, onefile, use_console, output_dir):
            success_count += 1
        else:
            failed.append(name)
    
    print(f"\n{'='*60}")
    print(f"Build Summary")
    print(f"{'='*60}")
    print(f"Successful: {success_count}/{len(ENTRY_POINTS)}")
    
    if failed:
        print(f"Failed: {', '.join(failed)}")
        return False
    
    print("All builds completed successfully!")
    return True


def create_batch_launcher(output_dir: Path):
    """Create batch file launcher for Windows."""
    
    batch_content = '''@echo off
REM Bitcoin Python Tools Launcher
REM This script helps run Bitcoin Python executables

setlocal enabledelayedexpansion

:menu
cls
echo ========================================
echo   Bitcoin Python Tools v0.1.0
echo ========================================
echo.
echo   1. Start Bitcoin Node (bitcoind-py)
echo   2. Run Bitcoin CLI (bitcoin-cli-py)
echo   3. Run Wallet Tool (bitcoin-wallet-py)
echo   4. Exit
echo.
set /p choice="Select option (1-4): "

if "%choice%"=="1" goto node
if "%choice%"=="2" goto cli
if "%choice%"=="3" goto wallet
if "%choice%"=="4" goto end
goto menu

:node
echo.
echo Starting Bitcoin Node...
bitcoind-py.exe --help
pause
goto menu

:cli
echo.
set /p cmd="Enter CLI command (e.g., getblockchaininfo): "
bitcoin-cli-py.exe %cmd%
pause
goto menu

:wallet
echo.
bitcoin-wallet-py.exe --help
pause
goto menu

:end
echo Goodbye!
exit /b 0
'''
    
    batch_path = output_dir / "bitcoin-tools.bat"
    batch_path.write_text(batch_content)
    print(f"Created batch launcher: {batch_path}")


def create_readme(output_dir: Path):
    """Create README for the distribution."""
    
    readme_content = f'''# {PROJECT_NAME} v{PROJECT_VERSION}

## Executables

This distribution contains the following executables:

### bitcoind-py.exe
Bitcoin Node Server - The main Bitcoin node implementation.

Usage:
    bitcoind-py.exe [options]

Options:
    --help              Show help message
    --version           Show version
    --datadir=DIR       Specify data directory
    --rpcuser=USER      RPC username
    --rpcpassword=PASS  RPC password
    --rpcport=PORT      RPC port (default: 8332)

### bitcoin-cli-py.exe
Command-line client for interacting with the Bitcoin RPC server.

Usage:
    bitcoin-cli-py.exe [options] <command> [params]

Examples:
    bitcoin-cli-py.exe getblockchaininfo
    bitcoin-cli-py.exe getbalance
    bitcoin-cli-py.exe getnewaddress
    bitcoin-cli-py.exe sendtoaddress <address> <amount>

Options:
    --host, -H          RPC server host (default: 127.0.0.1)
    --port, -p          RPC server port (default: 8332)
    --user, -u          RPC username
    --password, -P      RPC password
    --json, -j          Output in JSON format

### bitcoin-wallet-py.exe
Wallet management tool for Bitcoin operations.

Usage:
    bitcoin-wallet-py.exe [options] <command>

## Quick Start

1. Start the node:
   bitcoind-py.exe --rpcuser=myuser --rpcpassword=mypass

2. In another terminal, use the CLI:
   bitcoin-cli-py.exe --user=myuser --password=mypass getblockchaininfo

## Notes

- These are standalone executables that do not require Python to be installed.
- The executables are built for Windows x64.
- For security, always use strong RPC credentials.
- This is a Python implementation of Bitcoin Core for educational purposes.

## License

MIT License

## More Information

See the original Bitcoin Core documentation: https://github.com/bitcoin/bitcoin
'''
    
    readme_path = output_dir / "README.txt"
    readme_path.write_text(readme_content)
    print(f"Created README: {readme_path}")


def main():
    parser = argparse.ArgumentParser(
        description=f"Build {PROJECT_NAME} executables using PyInstaller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python build_exe.py --all                    # Build all executables
    python build_exe.py --cli                    # Build only CLI
    python build_exe.py --all --onefile --clean  # Clean build all as single files
    python build_exe.py --node --no-onefile      # Build node as directory
        """
    )
    
    # Target selection
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--all", action="store_true", help="Build all executables")
    target_group.add_argument("--node", action="store_true", help="Build only bitcoind-py")
    target_group.add_argument("--cli", action="store_true", help="Build only bitcoin-cli-py")
    target_group.add_argument("--wallet", action="store_true", help="Build only bitcoin-wallet-py")
    
    # Build options
    parser.add_argument("--onefile", action="store_true", default=True, 
                        help="Create single executable file (default: True)")
    parser.add_argument("--no-onefile", dest="onefile", action="store_false",
                        help="Create executable directory instead")
    parser.add_argument("--console", action="store_true", default=True,
                        help="Show console window (default: True)")
    parser.add_argument("--clean", action="store_true", help="Clean build artifacts first")
    parser.add_argument("--output", "-o", type=str, help="Output directory")
    parser.add_argument("--launcher", action="store_true", help="Create batch launcher for Windows")
    
    args = parser.parse_args()
    
    # Default to building all if no target specified
    if not (args.all or args.node or args.cli or args.wallet):
        args.all = True
    
    # Clean if requested
    if args.clean:
        clean_build_artifacts()
    
    # Set output directory
    output_dir = Path(args.output) if args.output else None
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
    
    # Build selected targets
    success = True
    
    if args.all:
        success = build_all(args.onefile, args.console, output_dir)
    else:
        if args.node:
            name = "bitcoind-py"
            success = build_executable(name, ENTRY_POINTS[name], args.onefile, args.console, output_dir) and success
        
        if args.cli:
            name = "bitcoin-cli-py"
            success = build_executable(name, ENTRY_POINTS[name], args.onefile, args.console, output_dir) and success
        
        if args.wallet:
            name = "bitcoin-wallet-py"
            success = build_executable(name, ENTRY_POINTS[name], args.onefile, args.console, output_dir) and success
    
    # Create launcher and README
    if args.launcher and success and output_dir:
        create_batch_launcher(output_dir)
        create_readme(output_dir)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
