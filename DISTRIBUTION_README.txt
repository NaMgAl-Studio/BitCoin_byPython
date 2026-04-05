# Bitcoin Core Python Implementation v0.1.0

## Distribution Contents

This ZIP file contains the complete Bitcoin Python implementation, including:

### Client Components
- **bitcoin-cli-py**: Command-line interface for Bitcoin RPC
- **bitcoin-wallet-py**: Wallet management tool

### Server Components
- **bitcoind-py**: Bitcoin node server implementation
- **RPC Server**: JSON-RPC HTTP server with cookie-file authentication

### Directory Structure

```
bitcoin-python-v0.1.0/
├── src/bitcoin/           # Main source code
│   ├── node.py            # Full node implementation
│   ├── cli.py             # CLI client
│   ├── chain/             # Blockchain management
│   ├── coins/             # UTXO management
│   ├── consensus/         # Consensus rules & PoW
│   ├── crypto/            # Cryptographic functions
│   ├── mempool/           # Memory pool
│   ├── p2p/               # Peer-to-peer networking
│   ├── primitives/        # Basic data structures
│   ├── rpc/               # RPC server/client + REST API
│   ├── script/            # Bitcoin script interpreter
│   ├── util/              # Utilities
│   └── wallet/            # HD wallet (BIP32/39/44/49/84/86)
├── scripts/               # Entry point scripts
│   ├── bitcoind_py.py     # Node server entry
│   ├── bitcoin_cli_py.py  # CLI entry
│   └── bitcoin_wallet_py.py # Wallet entry
├── tests/                 # Unit tests
├── build_exe.py           # EXE builder script
├── create_distribution.py # Distribution packager
├── pyproject.toml         # Project configuration
├── requirements-build.txt # Build dependencies
└── README.md              # Full project documentation
```

## Quick Start

### Installation

1. Extract this ZIP file to your desired location
2. Install Python 3.11 or later
3. Install dependencies:

```bash
cd bitcoin-python-v0.1.0
pip install -e ".[dev]"
```

### Running the Node

```bash
# Start the Bitcoin node (mainnet by default)
python -m bitcoin.node

# Start on testnet4
python -m bitcoin.node --testnet4

# Start with custom RPC port
python -m bitcoin.node --rpcport=8332
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

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test
pytest tests/unit/test_crypto.py -v
```

## Building Executables

To create standalone executable files:

```bash
pip install -r requirements-build.txt
python build_exe.py --all --clean
```

The executables will be created in the `dist/` directory.

## Requirements

- Python >= 3.11
- coincurve >= 19.0.0 (optional, pure Python fallback available)
- cryptography >= 42.0.0
- pydantic >= 2.5.0
- fastapi >= 0.109.0
- uvicorn >= 0.27.0
- aiohttp >= 3.9.0
- pyzmq >= 25.1.0

## License

MIT License

## Links

- Original Bitcoin Core: https://github.com/bitcoin/bitcoin
- Documentation: See README.md in the project root

---
Created: 2026-04-05
