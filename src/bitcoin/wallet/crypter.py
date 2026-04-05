"""
Wallet Crypter Module.

This module provides encryption and decryption functionality for wallet
private keys using AES-256-CBC with key derivation.

Reference: Bitcoin Core src/wallet/crypter.h, src/wallet/crypter.cpp
"""

import hashlib
import os
import secrets
from dataclasses import dataclass, field
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Constants
WALLET_CRYPTO_KEY_SIZE = 32
WALLET_CRYPTO_SALT_SIZE = 8
WALLET_CRYPTO_IV_SIZE = 16


def secure_clear(data: bytearray):
    """
    Securely clear sensitive data from memory.
    Note: Python's memory management makes true secure clearing difficult,
    but this is a best-effort implementation.
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0


class SecureBytes:
    """
    A secure byte container that attempts to clear memory on deletion.
    """
    def __init__(self, data: bytes = b''):
        self._data = bytearray(data)

    def __del__(self):
        secure_clear(self._data)

    def __bytes__(self) -> bytes:
        return bytes(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __getitem__(self, index):
        return self._data[index]

    def __add__(self, other):
        return SecureBytes(bytes(self._data) + bytes(other))

    def get(self) -> bytes:
        return bytes(self._data)

    def set(self, data: bytes):
        secure_clear(self._data)
        self._data = bytearray(data)


# Type alias for keying material
CKeyingMaterial = SecureBytes


@dataclass
class CMasterKey:
    """
    Master key for wallet encryption.

    Private key encryption is done based on a CMasterKey,
    which holds a salt and random encryption key.

    CMasterKeys are encrypted using AES-256-CBC using a key
    derived using derivation method nDerivationMethod
    (0 == EVP_sha512()) and derivation iterations nDeriveIterations.
    """
    # Default/minimum number of key derivation rounds
    DEFAULT_DERIVE_ITERATIONS = 25000

    vch_crypted_key: bytes = field(default_factory=lambda: b'')
    vch_salt: bytes = field(default_factory=lambda: b'')
    n_derivation_method: int = 0
    n_derive_iterations: int = DEFAULT_DERIVE_ITERATIONS
    vch_other_derivation_parameters: bytes = field(default_factory=lambda: b'')

    def __post_init__(self):
        if not self.vch_salt:
            self.vch_salt = secrets.token_bytes(WALLET_CRYPTO_SALT_SIZE)
        if self.n_derive_iterations == 0:
            self.n_derive_iterations = self.DEFAULT_DERIVE_ITERATIONS

    @classmethod
    def create_new(cls) -> 'CMasterKey':
        """Create a new master key with random salt."""
        return cls(
            vch_salt=secrets.token_bytes(WALLET_CRYPTO_SALT_SIZE),
            n_derive_iterations=cls.DEFAULT_DERIVE_ITERATIONS,
            n_derivation_method=0,
            vch_other_derivation_parameters=b''
        )

    def serialize(self) -> bytes:
        """Serialize the master key for storage."""
        result = bytearray()
        # Write crypted key length and data
        result.extend(len(self.vch_crypted_key).to_bytes(4, 'little'))
        result.extend(self.vch_crypted_key)
        # Write salt length and data
        result.extend(len(self.vch_salt).to_bytes(4, 'little'))
        result.extend(self.vch_salt)
        # Write derivation method and iterations
        result.extend(self.n_derivation_method.to_bytes(4, 'little'))
        result.extend(self.n_derive_iterations.to_bytes(4, 'little'))
        # Write other parameters length and data
        result.extend(len(self.vch_other_derivation_parameters).to_bytes(4, 'little'))
        result.extend(self.vch_other_derivation_parameters)
        return bytes(result)

    @classmethod
    def deserialize(cls, data: bytes) -> 'CMasterKey':
        """Deserialize a master key from storage."""
        offset = 0

        # Read crypted key
        key_len = int.from_bytes(data[offset:offset+4], 'little')
        offset += 4
        vch_crypted_key = data[offset:offset+key_len]
        offset += key_len

        # Read salt
        salt_len = int.from_bytes(data[offset:offset+4], 'little')
        offset += 4
        vch_salt = data[offset:offset+salt_len]
        offset += salt_len

        # Read derivation method and iterations
        n_derivation_method = int.from_bytes(data[offset:offset+4], 'little')
        offset += 4
        n_derive_iterations = int.from_bytes(data[offset:offset+4], 'little')
        offset += 4

        # Read other parameters
        other_len = int.from_bytes(data[offset:offset+4], 'little')
        offset += 4
        vch_other_derivation_parameters = data[offset:offset+other_len]

        return cls(
            vch_crypted_key=vch_crypted_key,
            vch_salt=vch_salt,
            n_derivation_method=n_derivation_method,
            n_derive_iterations=n_derive_iterations,
            vch_other_derivation_parameters=vch_other_derivation_parameters
        )


class CCrypter:
    """
    Encryption/decryption context with key information.

    Provides AES-256-CBC encryption for wallet private keys.
    """

    def __init__(self):
        self._vch_key: bytearray = bytearray(WALLET_CRYPTO_KEY_SIZE)
        self._vch_iv: bytearray = bytearray(WALLET_CRYPTO_IV_SIZE)
        self._f_key_set: bool = False

    def __del__(self):
        self.clean_key()

    def clean_key(self):
        """Securely clear the encryption key."""
        secure_clear(self._vch_key)
        secure_clear(self._vch_iv)
        self._f_key_set = False

    def _bytes_to_key_sha512_aes(
        self,
        salt: bytes,
        key_data: bytes,
        count: int
    ) -> Tuple[bytes, bytes]:
        """
        Derive key and IV from passphrase using SHA512-based key derivation.

        This is equivalent to OpenSSL's EVP_BytesToKey with SHA512.
        """
        # Initial hash
        d = hashlib.sha512(salt + key_data).digest()

        # Iterate
        for _ in range(count - 1):
            d = hashlib.sha512(d).digest()

        # Split into key (32 bytes) and IV (16 bytes)
        key = d[:WALLET_CRYPTO_KEY_SIZE]
        iv = d[WALLET_CRYPTO_KEY_SIZE:WALLET_CRYPTO_KEY_SIZE + WALLET_CRYPTO_IV_SIZE]

        return key, iv

    def set_key_from_passphrase(
        self,
        key_data: bytes,
        salt: bytes,
        rounds: int,
        derivation_method: int
    ) -> bool:
        """
        Derive encryption key from passphrase.

        Args:
            key_data: The passphrase bytes
            salt: Random salt
            rounds: Number of derivation iterations
            derivation_method: 0 for SHA512

        Returns:
            True if key was successfully set
        """
        if len(salt) != WALLET_CRYPTO_SALT_SIZE:
            return False

        if derivation_method != 0:
            return False

        key, iv = self._bytes_to_key_sha512_aes(salt, key_data, rounds)

        self._vch_key = bytearray(key)
        self._vch_iv = bytearray(iv)
        self._f_key_set = True

        return True

    def set_key(self, new_key: bytes, new_iv: bytes) -> bool:
        """
        Directly set the encryption key and IV.

        Args:
            new_key: 32-byte key
            new_iv: 16-byte IV

        Returns:
            True if key was successfully set
        """
        if len(new_key) != WALLET_CRYPTO_KEY_SIZE:
            return False
        if len(new_iv) != WALLET_CRYPTO_IV_SIZE:
            return False

        self._vch_key = bytearray(new_key)
        self._vch_iv = bytearray(new_iv)
        self._f_key_set = True

        return True

    def encrypt(self, plaintext: bytes) -> Optional[bytes]:
        """
        Encrypt plaintext using AES-256-CBC.

        Args:
            plaintext: Data to encrypt

        Returns:
            Encrypted ciphertext or None on failure
        """
        if not self._f_key_set:
            return None

        try:
            # Pad plaintext to block size (PKCS7)
            block_size = 16
            padding_len = block_size - (len(plaintext) % block_size)
            padded_plaintext = plaintext + bytes([padding_len] * padding_len)

            # Create cipher
            cipher = Cipher(
                algorithms.AES(bytes(self._vch_key)),
                modes.CBC(bytes(self._vch_iv)),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()

            # Encrypt
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

            return ciphertext

        except Exception:
            return None

    def decrypt(self, ciphertext: bytes) -> Optional[bytes]:
        """
        Decrypt ciphertext using AES-256-CBC.

        Args:
            ciphertext: Data to decrypt

        Returns:
            Decrypted plaintext or None on failure
        """
        if not self._f_key_set:
            return None

        if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
            return None

        try:
            # Create cipher
            cipher = Cipher(
                algorithms.AES(bytes(self._vch_key)),
                modes.CBC(bytes(self._vch_iv)),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()

            # Decrypt
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove PKCS7 padding
            padding_len = padded_plaintext[-1]
            if padding_len > 16 or padding_len == 0:
                return None

            # Verify padding
            for i in range(padding_len):
                if padded_plaintext[-(i+1)] != padding_len:
                    return None

            plaintext = padded_plaintext[:-padding_len]

            return plaintext

        except Exception:
            return None


def encrypt_secret(
    master_key: CKeyingMaterial,
    plaintext: bytes,
    n_iv: bytes
) -> Optional[bytes]:
    """
    Encrypt a secret (e.g., private key) using the master key.

    Args:
        master_key: The master encryption key
        plaintext: The secret to encrypt
        n_iv: 32-byte IV (typically hash of public key)

    Returns:
        Encrypted secret or None on failure
    """
    if len(master_key) != WALLET_CRYPTO_KEY_SIZE:
        return None

    crypter = CCrypter()

    # Derive IV from n_iv
    iv = hashlib.sha256(n_iv).digest()[:WALLET_CRYPTO_IV_SIZE]

    if not crypter.set_key(bytes(master_key), iv):
        return None

    return crypter.encrypt(plaintext)


def decrypt_secret(
    master_key: CKeyingMaterial,
    ciphertext: bytes,
    n_iv: bytes
) -> Optional[bytes]:
    """
    Decrypt a secret using the master key.

    Args:
        master_key: The master encryption key
        ciphertext: The encrypted secret
        n_iv: 32-byte IV (same as used for encryption)

    Returns:
        Decrypted secret or None on failure
    """
    if len(master_key) != WALLET_CRYPTO_KEY_SIZE:
        return None

    crypter = CCrypter()

    # Derive IV from n_iv
    iv = hashlib.sha256(n_iv).digest()[:WALLET_CRYPTO_IV_SIZE]

    if not crypter.set_key(bytes(master_key), iv):
        return None

    return crypter.decrypt(ciphertext)


def decrypt_key(
    master_key: CKeyingMaterial,
    crypted_secret: bytes,
    pub_key: bytes
) -> Optional[bytes]:
    """
    Decrypt a private key using the master key.

    The IV is derived from the public key (double SHA256).

    Args:
        master_key: The master encryption key
        crypted_secret: The encrypted private key
        pub_key: The corresponding public key

    Returns:
        Decrypted private key or None on failure
    """
    # IV is double SHA256 of public key
    iv = hashlib.sha256(hashlib.sha256(pub_key).digest()).digest()

    secret = decrypt_secret(master_key, crypted_secret, iv)
    if secret is None:
        return None

    # Verify the secret length (should be 32 bytes for secp256k1)
    if len(secret) != 32:
        return None

    return secret


def generate_random_key() -> bytes:
    """Generate a random 32-byte key."""
    return secrets.token_bytes(WALLET_CRYPTO_KEY_SIZE)


def generate_random_iv() -> bytes:
    """Generate a random 16-byte IV."""
    return secrets.token_bytes(WALLET_CRYPTO_IV_SIZE)


def generate_random_salt() -> bytes:
    """Generate a random 8-byte salt."""
    return secrets.token_bytes(WALLET_CRYPTO_SALT_SIZE)
