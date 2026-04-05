# Bitcoin Core Python Implementation

A Python implementation of Bitcoin Core, providing a full node, wallet, RPC server, and all core consensus logic — following the original C++ implementation closely.


## Project Structure

```bash
bitcoin-python/
├── src/bitcoin/
│   ├── __init__.py
│   ├── node.py                  # Full node implementation
│   ├── cli.py                   # CLI client
│   ├── chain/                   # Blockchain management
│   │   └── chain.py
│   ├── coins/                   # UTXO management
│   │   └── coins.py
│   ├── consensus/               # Consensus rules
│   │   ├── amount.py            # Bitcoin amounts
│   │   ├── consensus.py         # Constants
│   │   ├── merkle.py            # Merkle trees
│   │   ├── params.py            # Network parameters
│   │   ├── pow.py               # Proof-of-work
│   │   ├── tx_check.py          # Transaction checks
│   │   ├── tx_verify.py         # Transaction verification
│   │   └── validation.py        # Validation states
│   ├── crypto/                  # Cryptographic primitives
│   │   ├── sha256.py            # SHA-256
│   │   ├── sha512.py            # SHA-512
│   │   ├── ripemd160.py         # RIPEMD-160
│   │   ├── hmac.py              # HMAC
│   │   ├── hkdf.py              # HKDF
│   │   ├── siphash.py           # SipHash
│   │   └── common.py            # Byte utilities
│   ├── mempool/                 # Memory pool
│   │   └── mempool.py
│   ├── p2p/                     # Peer-to-peer networking
│   │   ├── addrman.py           # Address book
│   │   ├── blockdownload.py     # Block downloader
│   │   ├── connman.py           # Connection manager
│   │   ├── dnsseed.py           # DNS seed discovery
│   │   ├── messages.py          # Network messages
│   │   ├── netaddress.py        # Network addresses
│   │   ├── netbase.py           # Network base
│   │   ├── protocol.py          # Wire protocol
│   │   ├── transport.py         # Transport layer
│   │   └── txbroadcast.py       # Transaction broadcast
│   ├── primitives/              # Data structures
│   │   ├── transaction.py       # TxIn, TxOut, Transaction
│   │   └── block.py             # BlockHeader, Block
│   ├── rpc/                     # RPC server/client
│   │   ├── server.py            # JSON-RPC server
│   │   ├── client.py            # RPC client
│   │   ├── auth.py              # Authentication
│   │   ├── httpserver.py        # HTTP server
│   │   ├── rest.py              # REST API
│   │   ├── methods_blockchain.py
│   │   ├── methods_wallet.py
│   │   ├── protocol.py
│   │   ├── request.py
│   │   └── util.py
│   ├── script/                  # Bitcoin script interpreter
│   │   ├── interpreter.py       # Script interpreter
│   │   ├── opcodes.py           # Opcode definitions
│   │   ├── script.py            # CScript
│   │   ├── sighash.py           # Signature hash
│   │   ├── signature_checker.py # Signature verification
│   │   ├── solver.py            # Script solver
│   │   ├── taproot.py           # Taproot support
│   │   ├── sigversion.py        # Signature versions
│   │   ├── script_error.py      # Script errors
│   │   └── verify_flags.py      # Verification flags
│   ├── util/                    # Utilities
│   │   ├── strencodings.py      # String encodings
│   │   ├── string.py            # String utilities
│   │   └── time.py              # Time utilities
│   └── wallet/                  # Wallet implementation
│       ├── wallet.py            # Core wallet
│       ├── hd.py                # HD key derivation (BIP32/39)
│       ├── coinselection.py     # Coin selection
│       ├── crypter.py           # Encryption
│       ├── db.py                # SQLite database
│       ├── transaction.py       # Transaction building
│       ├── spend.py             # Spend logic
│       ├── types.py             # Wallet types
│       ├── walletdb.py          # Wallet DB
│       ├── cli.py               # Wallet CLI
│       └── keys.py              # Key management
├── scripts/                     # Entry point scripts
│   ├── bitcoind_py.py           # Node server entry
│   ├── bitcoin_cli_py.py        # CLI entry
│   └── bitcoin_wallet_py.py     # Wallet entry
├── tests/
│   └── unit/                    # Unit tests
│       ├── test_crypto.py
│       ├── test_primitives.py
│       ├── test_consensus.py
│       ├── test_script.py
│       ├── test_rpc.py
│       ├── test_wallet.py
│       └── test_util.py
├── pyproject.toml               # Project configuration
├── build_exe.py                 # EXE builder (PyInstaller)
├── create_distribution.py       # Distribution packager
├── requirements-build.txt       # Build dependencies
└── README.md
```

## Building Executables

To create standalone executable files:

```bash
pip install -r requirements-build.txt
python build_exe.py --all --clean
```

The executables will be created in the `dist/` directory.

## Python Executables
- `bitcoind-py` — Bitcoin node server
- `bitcoin-cli-py` — RPC command-line client
- `bitcoin-wallet-py` — Wallet management tool

## Dependencies

### Runtime
- `coincurve` — libsecp256k1 bindings (optional, pure Python fallback available)
- `cryptography` — Additional crypto primitives
- `pydantic` — Data validation
- `fastapi` + `uvicorn` — HTTP server for RPC
- `aiohttp` — Async HTTP client
- `pyzmq` — ZeroMQ messaging


## License

MIT License

## References

- [Bitcoin Core](https://github.com/bitcoin/bitcoin)
- [Bitcoin Developer Documentation](https://developer.bitcoin.org/)
- [BIPs](https://github.com/bitcoin/bips)
