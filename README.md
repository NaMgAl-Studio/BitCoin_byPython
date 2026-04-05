# Bitcoin Core Python Implementation

A Python implementation of Bitcoin Core, providing a full node, wallet, RPC server, and all core consensus logic — following the original C++ implementation closely.

## Implemented Modules

### Primitives (Transaction & Block Data Structures)
- ✅ `OutPoint` - Transaction output reference
- ✅ `TxIn` - Transaction input
- ✅ `TxOut` - Transaction output
- ✅ `Transaction` - Complete transaction with serialization
- ✅ `MutableTransaction` - Mutable transaction builder
- ✅ `BlockHeader` - 80-byte block header
- ✅ `Block` - Complete block with transactions
- ✅ `BlockLocator` - Chain synchronization helper
- ✅ `Txid` / `Wtxid` - Transaction identifiers

### Consensus (Rules & Validation)
- ✅ `ConsensusParams` - Network parameters (mainnet/testnet4/regtest)
- ✅ `CAmount`, `COIN`, `MAX_MONEY` - Monetary constants
- ✅ `BlockMerkleRoot` - Merkle tree computation
- ✅ `ValidationState` - Validation error handling
- ✅ `CheckProofOfWork` / `ArithUint256` - Proof-of-work verification & difficulty math
- ✅ `TxCheck` / `TxVerify` - Transaction validation
- ✅ Consensus constants (block limits, sigops, maturity)
- ✅ Block subsidy & halving logic

### Script Engine (Bitcoin Script Interpreter)
- ✅ Full opcode set (`OP_*`) with names and decoding
- ✅ `CScript` - Script data structure with push operations
- ✅ `SignatureHash` dispatcher (Legacy / BIP143 / BIP341)
- ✅ Legacy signature hash implementation
- ✅ `ScriptInterpreter` - Stack-based interpreter
- ✅ `SignatureChecker` - ECDSA & Schnorr signature verification
- ✅ `ScriptError` - Error handling with full error type enumeration
- ✅ Taproot support (script path, key path)
- ✅ Script solver (`IsMine`, `ExtractDestinations`, etc.)
- ✅ Verification flags (`SCRIPT_VERIFY_*`)

### Crypto (Cryptographic Primitives)
- ✅ `SHA256` / `double_sha256` - SHA-256 with double-SHA256
- ✅ `SHA512` - SHA-512 for BIP32
- ✅ `RIPEMD160` / `hash160` - For address generation
- ✅ `HMAC_SHA256` / `HMAC_SHA512` - HMAC implementations
- ✅ `HKDF_SHA256_L32` - Key derivation (BIP324)
- ✅ `SipHasher` / `PresaltedSipHasher` - SipHash-2-4
- ✅ Byte manipulation functions (ReadLE/BE, WriteLE/BE)

### Chain (Blockchain Management)
- ✅ `ChainstateManager` - Chain state management
- ✅ Block validation & connection
- ✅ Chain synchronization (IBD, headers-first)
- ✅ Block locator generation

### Coins (UTXO Management)
- ✅ `CoinsViewDB` - In-memory UTXO database
- ✅ `CoinsView` / `CCoins` - UTXO set abstraction
- ✅ Coin lookup, addition, and spending

### P2P Networking (Peer-to-Peer Protocol)
- ✅ `CConnman` - Connection manager
- ✅ `CAddrMan` - Address book management
- ✅ `ConnectionRateLimiter` - Connection rate limiting
- ✅ DNS seed discovery (`dnsseed.py`)
- ✅ Network message protocol (`protocol.py`)
- ✅ Transport layer (`transport.py`)
- ✅ Block download manager (`blockdownload.py`)
- ✅ Transaction broadcast (`txbroadcast.py`)
- ✅ `CNetAddr` / `CService` - Network address types
- ✅ Bitcoin message types (`messages.py`)

### Wallet (HD Wallet & Transaction Building)
- ✅ `BIP39` mnemonic (full 2048-word list, PBKDF2 seed derivation)
- ✅ `BIP32` HD key derivation (master key, child key, hardened derivation)
- ✅ `BIP44`/`BIP49`/`BIP84`/`BIP86` path helpers
- ✅ `secp256k1` - Pure Python elliptic curve (point multiplication, signing)
- ✅ WIF key encoding/decoding
- ✅ Wallet encryption (`CCrypter`, AES-256-CBC)
- ✅ SQLite wallet database
- ✅ Coin selection (Knapsack, SRD algorithms)
- ✅ `create_transaction()` - Full transaction building (UTXO selection, fees, change, signing)
- ✅ Wallet types, metadata, and address book

### Mempool (Memory Pool)
- ✅ `CTxMemPool` - Transaction pool
- ✅ Fee estimation
- ✅ Mempool policy checks

### RPC / REST (API Layer)
- ✅ JSON-RPC server (HTTP)
- ✅ RPC authentication (username/password + cookie file)
- ✅ Blockchain RPC methods (`getblockchaininfo`, `getblock`, etc.)
- ✅ Wallet RPC methods (`getbalance`, `sendtoaddress`, `getnewaddress`, etc.)
- ✅ REST API endpoints
- ✅ CLI client (`bitcoin-cli-py`)

### Node (Full Node)
- ✅ `BitcoinNode` - Main node class
- ✅ Mainnet / Testnet4 / Regtest support
- ✅ Automatic random RPC credential generation
- ✅ `.cookie` file for authentication
- ✅ CLI entry points (`bitcoind-py`, `bitcoin-cli-py`, `bitcoin-wallet-py`)

### Utilities
- ✅ `HexStr`, `ParseHex`, `IsHex` - Hex encoding
- ✅ `EncodeBase64` / `DecodeBase64` - Base64
- ✅ `EncodeBase32` / `DecodeBase32` - Base32 (Bech32)
- ✅ `SanitizeString` - String sanitization
- ✅ `TimingResistantEqual` - Constant-time comparison
- ✅ `ConvertBits` - Bit conversion for Bech32
- ✅ Time utilities (GetTime, ISO8601 parsing)

```

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
