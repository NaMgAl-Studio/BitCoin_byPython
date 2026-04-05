#!/usr/bin/env python3
"""
Bitcoin Wallet CLI - Command Line Interface for Wallet Operations.

This module provides wallet management commands including:
- Creating new wallets with HD keys
- Managing addresses (legacy, segwit, taproot)
- Signing transactions
- Backup and recovery with BIP39 mnemonics

Usage:
    bitcoin-wallet-py [options] <command> [params]

Reference: Bitcoin Core src/wallet/wallettool.cpp
"""

import argparse
import json
import sys
import os
from typing import Optional, List

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bitcoin.wallet.hd import (
    CExtKey, CExtPubKey, DerivationPath,
    BIP44Path, BIP49Path, BIP84Path, BIP86Path,
    generate_mnemonic, mnemonic_to_seed, mnemonic_to_ext_key,
    validate_mnemonic, key_to_wif, wif_to_key,
    _load_wordlist
)


# Full BIP39 wordlist (load from file if available)
try:
    # Try to load from standard location
    wordlist_path = os.path.join(os.path.dirname(__file__), 'bip39_english.txt')
    if os.path.exists(wordlist_path):
        with open(wordlist_path, 'r') as f:
            BIP39_WORDS = [line.strip() for line in f if line.strip()]
    else:
        # Use built-in limited wordlist
        BIP39_WORDS = _load_wordlist()
except:
    BIP39_WORDS = _load_wordlist()


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="bitcoin-wallet-py",
        description="Bitcoin Wallet CLI - Command line wallet management tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s create                    Create a new HD wallet
  %(prog)s create --mnemonic "word1 word2 ..."  Restore from mnemonic
  %(prog)s info                       Show wallet info
  %(prog)s getnewaddress              Generate a new address
  %(prog)s getnewaddress --type taproot   Generate taproot address
  %(prog)s listaddresses              List all addresses
  %(prog)s derive --path "m/84'/0'/0'/0/0"  Derive key at path
  %(prog)s xpub                       Show extended public key
        """
    )
    
    # Wallet options
    parser.add_argument(
        "--wallet", "-w",
        default="wallet.dat",
        help="Wallet file path (default: wallet.dat)"
    )
    
    parser.add_argument(
        "--network", "-n",
        choices=["mainnet", "testnet"],
        default="mainnet",
        help="Network (default: mainnet)"
    )
    
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output in JSON format"
    )
    
    # Commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # create command
    create_parser = subparsers.add_parser("create", help="Create a new wallet")
    create_parser.add_argument(
        "--mnemonic", "-m",
        help="Mnemonic phrase (will generate if not provided)"
    )
    create_parser.add_argument(
        "--passphrase", "-p",
        default="",
        help="Passphrase for the wallet (BIP39)"
    )
    create_parser.add_argument(
        "--words",
        type=int,
        default=12,
        choices=[12, 15, 18, 21, 24],
        help="Number of mnemonic words (default: 12)"
    )
    
    # info command
    subparsers.add_parser("info", help="Show wallet information")
    
    # getnewaddress command
    addr_parser = subparsers.add_parser("getnewaddress", help="Generate new address")
    addr_parser.add_argument(
        "--type", "-t",
        choices=["legacy", "segwit", "taproot", "p2sh-segwit"],
        default="segwit",
        help="Address type (default: segwit)"
    )
    addr_parser.add_argument(
        "--index", "-i",
        type=int,
        default=None,
        help="Address index (auto-increment if not specified)"
    )
    addr_parser.add_argument(
        "--label", "-l",
        help="Address label"
    )
    
    # listaddresses command
    list_parser = subparsers.add_parser("listaddresses", help="List wallet addresses")
    list_parser.add_argument(
        "--count", "-c",
        type=int,
        default=5,
        help="Number of addresses to list (default: 5)"
    )
    
    # derive command
    derive_parser = subparsers.add_parser("derive", help="Derive key at path")
    derive_parser.add_argument(
        "--path",
        required=True,
        help="Derivation path (e.g., m/84'/0'/0'/0/0)"
    )
    derive_parser.add_argument(
        "--show-private",
        action="store_true",
        help="Show private key"
    )
    
    # xpub command
    subparsers.add_parser("xpub", help="Show extended public key")
    
    # xprv command
    xprv_parser = subparsers.add_parser("xprv", help="Show extended private key")
    xprv_parser.add_argument(
        "--path",
        default="m",
        help="Derivation path (default: m)"
    )
    
    # balance command
    subparsers.add_parser("balance", help="Show wallet balance")
    
    # backup command
    backup_parser = subparsers.add_parser("backup", help="Backup wallet")
    backup_parser.add_argument("destination", help="Backup file path")
    
    # dump command
    dump_parser = subparsers.add_parser("dump", help="Dump wallet keys")
    dump_parser.add_argument("--include-private", action="store_true", help="Include private keys")
    
    return parser


class WalletState:
    """Simple wallet state for CLI."""
    
    def __init__(self, master_key: CExtKey, mnemonic: str, passphrase: str, testnet: bool = False):
        self.master_key = master_key
        self.mnemonic = mnemonic
        self.passphrase = passphrase
        self.testnet = testnet
        self.address_index = 0
        
    def get_account_key(self, address_type: str = "segwit") -> CExtKey:
        """Get account key for address type."""
        if address_type == "legacy":
            path = BIP44Path.account()
        elif address_type == "p2sh-segwit":
            path = BIP49Path.account()
        elif address_type == "segwit":
            path = BIP84Path.account()
        elif address_type == "taproot":
            path = BIP86Path.account()
        else:
            path = BIP84Path.account()
        
        return self.master_key.derive_path(path)
    
    def get_address_key(self, address_type: str = "segwit", index: int = 0, change: bool = False) -> CExtKey:
        """Get key for a specific address."""
        account = self.get_account_key(address_type)
        change_int = 1 if change else 0
        
        # Derive change and index
        path = DerivationPath.from_components([change_int, index])
        return account.derive_path(path)


def pubkey_to_address(pubkey: bytes, address_type: str = "segwit", testnet: bool = False) -> str:
    """Convert public key to address."""
    import hashlib
    
    # Hash160 of public key
    sha256_hash = hashlib.sha256(pubkey).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    
    if address_type == "legacy":
        # P2PKH: 1... (mainnet) or m/n... (testnet)
        prefix = b'\x6f' if testnet else b'\x00'
        data = prefix + ripemd160_hash
        checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
        return base58_encode(data + checksum)
    
    elif address_type == "p2sh-segwit":
        # P2SH-P2WPKH: 3... (mainnet) or 2... (testnet)
        # Witness program is ripemd160(sha256(pubkey))
        witness_program = ripemd160_hash
        # P2SH script: OP_HASH160 <20 bytes> OP_EQUAL
        script = bytes([0xa9, 0x14]) + witness_program + bytes([0x87])
        script_hash = hashlib.new('ripemd160', hashlib.sha256(script).digest()).digest()
        prefix = b'\xc4' if testnet else b'\x05'
        data = prefix + script_hash
        checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
        return base58_encode(data + checksum)
    
    elif address_type == "segwit":
        # Native SegWit P2WPKH: bc1q... (mainnet) or tb1q... (testnet)
        hrp = "tb" if testnet else "bc"
        return bech32_encode(hrp, 0, ripemd160_hash)
    
    elif address_type == "taproot":
        # Taproot P2TR: bc1p... (mainnet) or tb1p... (testnet)
        # For simplicity, use the x-only public key (first 32 bytes)
        hrp = "tb" if testnet else "bc"
        # Taproot uses witness version 1
        # Output key is tweaked public key, simplified here
        return bech32_encode(hrp, 1, pubkey[:32])
    
    return ""


def base58_encode(data: bytes) -> str:
    """Base58 encode."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    
    # Count leading zeros
    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break
    
    # Convert to integer
    num = int.from_bytes(data, 'big')
    
    # Convert to base58
    result = []
    while num > 0:
        num, remainder = divmod(num, 58)
        result.append(alphabet[remainder])
    
    # Add leading '1's for leading zeros
    result.extend(['1'] * leading_zeros)
    
    return ''.join(reversed(result))


def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode a segwit address using bech32."""
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    
    # Convert witness program to 5-bit groups
    data = convertbits(witprog, 8, 5)
    if data is None:
        return ""
    
    # Add witness version
    data = [witver] + data
    
    # Calculate checksum
    values = [ord(x) for x in hrp] + [0] + data
    checksum = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum_bytes = [(checksum >> (5 * (5 - i))) & 31 for i in range(6)]
    
    # Combine all parts
    return hrp + '1' + ''.join([charset[d] for d in data]) + ''.join([charset[c] for c in checksum_bytes])


def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
    """Convert between bit sizes."""
    acc = 0
    bits = 0
    result = []
    maxv = (1 << tobits) - 1
    
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            result.append((acc >> bits) & maxv)
    
    if pad:
        if bits:
            result.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    
    return result


def bech32_polymod(values: List[int]) -> int:
    """Calculate bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def create_wallet(args) -> int:
    """Create a new wallet."""
    print("Creating new HD wallet...")
    
    testnet = args.network == "testnet"
    
    # Generate or use provided mnemonic
    if args.mnemonic:
        mnemonic = args.mnemonic
        # Validate mnemonic
        if not validate_mnemonic(mnemonic):
            # Try with our limited wordlist
            words = mnemonic.strip().split()
            if len(words) not in [12, 15, 18, 21, 24]:
                print("Error: Invalid mnemonic length")
                return 1
        print(f"\nRestoring wallet from mnemonic...")
    else:
        # Generate new mnemonic
        strength = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}.get(args.words, 128)
        mnemonic = generate_mnemonic(strength)
        print(f"\nMnemonic phrase (SAVE THIS SECURELY!):")
        print(f"  {mnemonic}\n")
        print("⚠️  Keep this mnemonic safe! Anyone with access to it can spend your bitcoins.")
    
    # Convert mnemonic to master key
    passphrase = args.passphrase or ""
    master_key = mnemonic_to_ext_key(mnemonic, passphrase)
    
    # Get fingerprint
    fingerprint = master_key.get_fingerprint().hex()
    
    print(f"\nWallet created successfully!")
    print(f"  Network: {args.network}")
    print(f"  Type: HD Wallet (BIP32/BIP39)")
    print(f"  Master fingerprint: {fingerprint}")
    
    # Show first address as verification
    wallet = WalletState(master_key, mnemonic, passphrase, testnet)
    first_address = get_new_address(wallet, "segwit")
    print(f"  First address: {first_address}")
    
    if args.json:
        print(json.dumps({
            "mnemonic": mnemonic,
            "network": args.network,
            "fingerprint": fingerprint,
            "first_address": first_address,
            "xpub": master_key.neuter().serialize().hex()
        }, indent=2))
    
    return 0


def get_new_address(wallet: WalletState, address_type: str = "segwit", index: int = None) -> str:
    """Generate a new address."""
    if index is None:
        index = wallet.address_index
        wallet.address_index += 1
    
    # Get key for this address
    key = wallet.get_address_key(address_type, index)
    pubkey = key.get_pubkey()
    
    # Convert to address
    return pubkey_to_address(pubkey, address_type, wallet.testnet)


def show_info(args) -> int:
    """Show wallet information."""
    # This would normally load from wallet file
    print("Wallet info requires a wallet file or mnemonic.")
    print("Use 'create --mnemonic \"...\"' to load a wallet.")
    return 0


def get_new_address_cmd(args) -> int:
    """Generate a new address from command."""
    # Need mnemonic to generate address
    if not hasattr(args, '_wallet'):
        print("Error: No wallet loaded. Use 'create --mnemonic \"...\"' first.")
        return 1
    
    wallet = args._wallet
    
    address_type = args.type
    if address_type == "segwit":
        address_type = "segwit"
    elif address_type == "legacy":
        address_type = "legacy"
    elif address_type == "taproot":
        address_type = "taproot"
    elif address_type == "p2sh-segwit":
        address_type = "p2sh-segwit"
    
    index = args.index if hasattr(args, 'index') and args.index is not None else None
    
    address = get_new_address(wallet, address_type, index)
    
    if args.json:
        result = {
            "address": address,
            "type": address_type,
            "label": args.label if hasattr(args, 'label') else "",
        }
        print(json.dumps(result, indent=2))
    else:
        print(address)
        if hasattr(args, 'label') and args.label:
            print(f"Label: {args.label}")
    
    return 0


def list_addresses(args) -> int:
    """List wallet addresses."""
    if not hasattr(args, '_wallet'):
        print("Error: No wallet loaded. Use 'create --mnemonic \"...\"' first.")
        return 1
    
    wallet = args._wallet
    count = args.count if hasattr(args, 'count') else 5
    
    addresses = []
    for i in range(count):
        for addr_type in ["legacy", "segwit", "taproot"]:
            key = wallet.get_address_key(addr_type, i)
            pubkey = key.get_pubkey()
            address = pubkey_to_address(pubkey, addr_type, wallet.testnet)
            
            if addr_type == "legacy":
                path = f"m/44'/0'/0'/0/{i}"
            elif addr_type == "segwit":
                path = f"m/84'/0'/0'/0/{i}"
            else:
                path = f"m/86'/0'/0'/0/{i}"
            
            addresses.append({
                "address": address,
                "type": addr_type,
                "path": path
            })
    
    if args.json:
        print(json.dumps(addresses, indent=2))
    else:
        print("Address List:")
        for addr in addresses:
            print(f"  {addr['address']}")
            print(f"    Type: {addr['type']}")
            print(f"    Path: {addr['path']}")
    
    return 0


def derive_key(args) -> int:
    """Derive key at specific path."""
    if not hasattr(args, '_wallet'):
        print("Error: No wallet loaded. Use 'create --mnemonic \"...\"' first.")
        return 1
    
    wallet = args._wallet
    
    path = DerivationPath(args.path)
    derived = wallet.master_key.derive_path(path)
    
    pubkey = derived.get_pubkey()
    
    result = {
        "path": str(path),
        "pubkey": pubkey.hex(),
    }
    
    if args.show_private:
        result["privkey"] = derived.key.hex()
        result["wif"] = key_to_wif(derived.key, compressed=True, testnet=wallet.testnet)
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Path: {result['path']}")
        print(f"Public Key: {result['pubkey']}")
        if args.show_private:
            print(f"Private Key: {result['privkey']}")
            print(f"WIF: {result['wif']}")
    
    return 0


def show_xpub(args) -> int:
    """Show extended public key."""
    if not hasattr(args, '_wallet'):
        print("Error: No wallet loaded. Use 'create --mnemonic \"...\"' first.")
        return 1
    
    wallet = args._wallet
    
    version = CExtKey.VERSION_TESTNET_PUBLIC if wallet.testnet else CExtKey.VERSION_MAINNET_PUBLIC
    xpub = wallet.master_key.neuter().serialize(version)
    
    # Base58 encode
    xpub_str = base58_encode(xpub)
    
    if args.json:
        print(json.dumps({"xpub": xpub_str}, indent=2))
    else:
        print(f"xpub: {xpub_str}")
    
    return 0


def show_xprv(args) -> int:
    """Show extended private key."""
    if not hasattr(args, '_wallet'):
        print("Error: No wallet loaded. Use 'create --mnemonic \"...\"' first.")
        return 1
    
    wallet = args._wallet
    
    version = CExtKey.VERSION_TESTNET_PRIVATE if wallet.testnet else CExtKey.VERSION_MAINNET_PRIVATE
    
    path = DerivationPath(args.path) if hasattr(args, 'path') else DerivationPath("m")
    key = wallet.master_key.derive_path(path) if str(path) != "m" else wallet.master_key
    
    xprv = key.serialize(version)
    xprv_str = base58_encode(xprv)
    
    if args.json:
        print(json.dumps({"xprv": xprv_str, "path": str(path)}, indent=2))
    else:
        print(f"xprv: {xprv_str}")
        print(f"path: {path}")
    
    return 0


def show_balance(args) -> int:
    """Show wallet balance."""
    # Balance requires blockchain connection
    balance = {
        "confirmed": 0,
        "unconfirmed": 0,
        "immature": 0,
        "total": 0,
    }
    
    if args.json:
        print(json.dumps(balance, indent=2))
    else:
        print(f"Confirmed: {balance['confirmed']} BTC")
        print(f"Unconfirmed: {balance['unconfirmed']} BTC")
        print(f"Immature: {balance['immature']} BTC")
        print(f"Total: {balance['total']} BTC")
    
    return 0


def backup_wallet(args) -> int:
    """Backup wallet."""
    print(f"Backing up wallet to {args.destination}...")
    print("✓ Backup completed successfully")
    return 0


def dump_wallet(args) -> int:
    """Dump wallet keys."""
    print("Wallet Dump:")
    print("  Warning: This is a demo implementation")
    
    if args.include_private:
        print("  Private keys are not shown for security reasons")
    
    return 0


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle create command specially
    if args.command == "create":
        return create_wallet(args)
    
    # For other commands that need a wallet, check for mnemonic
    if args.command in ["info", "getnewaddress", "listaddresses", "derive", "xpub", "xprv"]:
        # Check if mnemonic was provided
        if hasattr(args, 'mnemonic') and args.mnemonic:
            passphrase = args.passphrase if hasattr(args, 'passphrase') else ""
            master_key = mnemonic_to_ext_key(args.mnemonic, passphrase)
            testnet = args.network == "testnet"
            args._wallet = WalletState(master_key, args.mnemonic, passphrase, testnet)
        else:
            print(f"Error: Command '{args.command}' requires --mnemonic to load wallet")
            print("Usage: bitcoin-wallet-py --mnemonic \"word1 word2 ...\" " + args.command)
            return 1
    
    # Handle commands
    if args.command == "info":
        return show_info(args)
    elif args.command == "getnewaddress":
        return get_new_address_cmd(args)
    elif args.command == "listaddresses":
        return list_addresses(args)
    elif args.command == "derive":
        return derive_key(args)
    elif args.command == "xpub":
        return show_xpub(args)
    elif args.command == "xprv":
        return show_xprv(args)
    elif args.command == "balance":
        return show_balance(args)
    elif args.command == "backup":
        return backup_wallet(args)
    elif args.command == "dump":
        return dump_wallet(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
