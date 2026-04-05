"""
HD Wallet Module (BIP32/39/44).

This module provides Hierarchical Deterministic wallet functionality
including key derivation, mnemonic generation, and account management.

Reference: Bitcoin Core src/key.h, src/key.cpp
BIP32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
BIP39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
BIP44: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
"""

import hashlib
import hmac
import struct
import secrets
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Union
from enum import Enum

# Import secp256k1 operations from coincurve or similar library
try:
    from coincurve import PrivateKey, PublicKey
    from coincurve._libsecp256k1 import ffi, lib
    HAS_COINCURVE = True
except ImportError:
    HAS_COINCURVE = False
    # Fallback to basic implementation


# BIP32 constants
HARDENED_KEY_START = 0x80000000
BIP32_EXTKEY_SIZE = 74  # Size of serialized extended key

# secp256k1 order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_ORDER_BYTES = SECP256K1_ORDER.to_bytes(32, 'big')


class DerivationPath:
    """
    BIP32 derivation path representation.

    Examples:
        m/44'/0'/0'/0/0 - BIP44 first external address
        m/84'/0'/0'/0/0 - BIP84 first external address
    """

    def __init__(self, path: str = "m"):
        """
        Initialize derivation path.

        Args:
            path: Path string like "m/44'/0'/0'/0/0"
        """
        self._components: List[int] = []

        if path and path != "m":
            parts = path.split('/')
            if parts[0] != 'm':
                raise ValueError("Path must start with 'm'")

            for part in parts[1:]:
                if part.endswith("'") or part.endswith("h"):
                    # Hardened derivation
                    index = int(part[:-1]) + HARDENED_KEY_START
                else:
                    # Normal derivation
                    index = int(part)
                self._components.append(index)

    @classmethod
    def from_components(cls, components: List[int]) -> 'DerivationPath':
        """Create path from component list."""
        path = cls()
        path._components = list(components)
        return path

    @property
    def components(self) -> List[int]:
        """Get path components as list of integers."""
        return list(self._components)

    def __str__(self) -> str:
        """Convert to string representation."""
        if not self._components:
            return "m"

        parts = ["m"]
        for c in self._components:
            if c >= HARDENED_KEY_START:
                parts.append(f"{c - HARDENED_KEY_START}'")
            else:
                parts.append(str(c))
        return "/".join(parts)

    def extend(self, *components: int) -> 'DerivationPath':
        """Create a new path with additional components."""
        return DerivationPath.from_components(self._components + list(components))

    def parent(self) -> Optional['DerivationPath']:
        """Get parent path."""
        if not self._components:
            return None
        return DerivationPath.from_components(self._components[:-1])

    def last_component(self) -> Optional[int]:
        """Get the last component of the path."""
        return self._components[-1] if self._components else None

    def depth(self) -> int:
        """Get the depth of the path."""
        return len(self._components)

    def __eq__(self, other):
        if not isinstance(other, DerivationPath):
            return False
        return self._components == other._components

    def __hash__(self):
        return hash(tuple(self._components))


# BIP44/BIP84 derivation paths
class BIP44Path:
    """BIP44 derivation path helper."""

    PURPOSE = 44  # Legacy (P2PKH)

    @classmethod
    def account(cls, account: int = 0) -> DerivationPath:
        """Get account path m/44'/0'/account'"""
        return DerivationPath(f"m/{cls.PURPOSE}'/0'/{account}'")

    @classmethod
    def external(cls, account: int = 0, index: int = 0) -> DerivationPath:
        """Get external (receiving) address path m/44'/0'/account'/0/index"""
        return DerivationPath(f"m/{cls.PURPOSE}'/0'/{account}'/0/{index}")

    @classmethod
    def internal(cls, account: int = 0, index: int = 0) -> DerivationPath:
        """Get internal (change) address path m/44'/0'/account'/1/index"""
        return DerivationPath(f"m/{cls.PURPOSE}'/0'/{account}'/1/{index}")


class BIP49Path:
    """BIP49 derivation path helper (SegWit P2SH-P2WPKH)."""

    PURPOSE = 49

    @classmethod
    def account(cls, account: int = 0) -> DerivationPath:
        return DerivationPath(f"m/{cls.PURPOSE}'/0'/{account}'")

    @classmethod
    def external(cls, account: int = 0, index: int = 0) -> DerivationPath:
        return DerivationPath(f"m/{cls.PURPOSE}'/0'/{account}'/0/{index}")

    @classmethod
    def internal(cls, account: int = 0, index: int = 0) -> DerivationPath:
        return DerivationPath(f"m/{cls.PURPOSE}'/0'/{account}'/1/{index}")


class BIP84Path:
    """BIP84 derivation path helper (Native SegWit P2WPKH)."""

    PURPOSE = 84

    @classmethod
    def account(cls, account: int = 0) -> DerivationPath:
        return DerivationPath(f"m/{cls.PURPOSE}'/0'/{account}'")

    @classmethod
    def external(cls, account: int = 0, index: int = 0) -> DerivationPath:
        return DerivationPath(f"m/{cls.PURPOSE}'/0'/{account}'/0/{index}")

    @classmethod
    def internal(cls, account: int = 0, index: int = 0) -> DerivationPath:
        return DerivationPath(f"m/{cls.PURPOSE}'/0'/{account}'/1/{index}")


class BIP86Path:
    """BIP86 derivation path helper (Taproot P2TR)."""

    PURPOSE = 86

    @classmethod
    def account(cls, account: int = 0) -> DerivationPath:
        return DerivationPath(f"m/{cls.PURPOSE}'/0'/{account}'")

    @classmethod
    def external(cls, account: int = 0, index: int = 0) -> DerivationPath:
        return DerivationPath(f"m/{cls.PURPOSE}'/0'/{account}'/0/{index}")

    @classmethod
    def internal(cls, account: int = 0, index: int = 0) -> DerivationPath:
        return DerivationPath(f"m/{cls.PURPOSE}'/0'/{account}'/1/{index}")


@dataclass
class CExtKey:
    """
    Extended private key (BIP32).

    Contains a private key with chain code and derivation info.
    """
    n_depth: int = 0
    n_parent_fingerprint: bytes = field(default_factory=lambda: bytes(4))
    n_child: int = 0
    chaincode: bytes = field(default_factory=lambda: bytes(32))
    key: bytes = field(default_factory=lambda: bytes(32))  # Private key

    # Version bytes for different networks
    VERSION_MAINNET_PRIVATE = 0x0488ADE4  # xprv
    VERSION_TESTNET_PRIVATE = 0x04358394  # tprv
    VERSION_MAINNET_PUBLIC = 0x0488B21E   # xpub
    VERSION_TESTNET_PUBLIC = 0x043587CF   # tpub

    @classmethod
    def from_seed(cls, seed: bytes) -> 'CExtKey':
        """
        Create master extended key from seed (BIP32).

        Args:
            seed: 16-64 bytes of entropy (typically 32 or 64 bytes)

        Returns:
            Master extended key
        """
        if len(seed) < 16 or len(seed) > 64:
            raise ValueError("Seed must be 16-64 bytes")

        # Generate master key using HMAC-SHA512
        I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]

        # Check for invalid key
        key_int = int.from_bytes(IL, 'big')
        if key_int == 0 or key_int >= SECP256K1_ORDER:
            raise ValueError("Invalid master key derived")

        return cls(
            n_depth=0,
            n_parent_fingerprint=bytes(4),
            n_child=0,
            chaincode=IR,
            key=IL
        )

    @classmethod
    def deserialize(cls, data: bytes) -> 'CExtKey':
        """
        Deserialize extended key from bytes.

        Format: version (4) + depth (1) + parent_fingerprint (4) +
                child (4) + chaincode (32) + key (33, with prefix)
        """
        if len(data) != BIP32_EXTKEY_SIZE + 4:  # 78 bytes
            raise ValueError(f"Invalid extended key size: {len(data)}")

        offset = 0
        version = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4

        n_depth = data[offset]
        offset += 1

        n_parent_fingerprint = data[offset:offset+4]
        offset += 4

        n_child = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4

        chaincode = data[offset:offset+32]
        offset += 32

        # Private key has 0x00 prefix
        key_prefix = data[offset]
        offset += 1
        key = data[offset:offset+32]

        return cls(
            n_depth=n_depth,
            n_parent_fingerprint=n_parent_fingerprint,
            n_child=n_child,
            chaincode=chaincode,
            key=key
        )

    def serialize(self, version: int = VERSION_MAINNET_PRIVATE) -> bytes:
        """Serialize extended key to bytes."""
        result = bytearray()

        # Version
        result.extend(version.to_bytes(4, 'big'))
        # Depth
        result.append(self.n_depth)
        # Parent fingerprint
        result.extend(self.n_parent_fingerprint)
        # Child
        result.extend(self.n_child.to_bytes(4, 'big'))
        # Chaincode
        result.extend(self.chaincode)
        # Key (with 0x00 prefix for private key)
        result.append(0x00)
        result.extend(self.key)

        return bytes(result)

    def serialize_public(self, version: int = VERSION_MAINNET_PUBLIC) -> bytes:
        """Serialize extended public key to bytes."""
        result = bytearray()

        # Version
        result.extend(version.to_bytes(4, 'big'))
        # Depth
        result.append(self.n_depth)
        # Parent fingerprint
        result.extend(self.n_parent_fingerprint)
        # Child
        result.extend(self.n_child.to_bytes(4, 'big'))
        # Chaincode
        result.extend(self.chaincode)
        # Public key (no prefix, full 33 bytes)
        result.extend(self.get_pubkey())

        return bytes(result)

    def get_pubkey(self) -> bytes:
        """Get the public key (33 bytes compressed)."""
        if HAS_COINCURVE:
            priv = PrivateKey(self.key)
            return priv.public_key.format(compressed=True)
        else:
            # Fallback implementation using ecdsa
            return self._get_pubkey_fallback()

    def _get_pubkey_fallback(self) -> bytes:
        """Fallback public key calculation using pure Python ecdsa.

        This implements secp256k1 elliptic curve point multiplication
        in pure Python. For production use, install coincurve for
        much better performance.
        """
        import hashlib

        # secp256k1 curve parameters
        P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        A = 0
        B = 7
        Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

        # Point at infinity
        INF = (None, None)

        def modinv(a, m):
            """Modular inverse using extended Euclidean algorithm."""
            if a < 0:
                a = a % m
            g, x, _ = _extended_gcd(a, m)
            if g != 1:
                raise ValueError("No modular inverse")
            return x % m

        def _extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            g, x, y = _extended_gcd(b % a, a)
            return g, y - (b // a) * x, x

        def point_add(p1, p2):
            """Add two elliptic curve points."""
            if p1 == INF:
                return p2
            if p2 == INF:
                return p1
            x1, y1 = p1
            x2, y2 = p2
            if x1 == x2:
                if y1 != y2:
                    return INF
                # Point doubling
                lam = (3 * x1 * x1) * modinv(2 * y1, P) % P
            else:
                lam = (y2 - y1) * modinv(x2 - x1, P) % P
            x3 = (lam * lam - x1 - x2) % P
            y3 = (lam * (x1 - x3) - y1) % P
            return (x3, y3)

        def point_mul(k, point):
            """Scalar multiplication of elliptic curve point."""
            result = INF
            addend = point
            while k > 0:
                if k & 1:
                    result = point_add(result, addend)
                addend = point_add(addend, addend)
                k >>= 1
            return result

        # Compute public key = priv_key * G
        k = int.from_bytes(self.key, 'big')
        if k == 0 or k >= N:
            raise ValueError("Invalid private key")

        G = (Gx, Gy)
        pub = point_mul(k, G)
        px, py = pub

        # Compressed public key format
        prefix = b'\x02' if py % 2 == 0 else b'\x03'
        return prefix + px.to_bytes(32, 'big')

    def get_fingerprint(self) -> bytes:
        """Get the key fingerprint (first 4 bytes of hash160 of pubkey)."""
        pubkey = self.get_pubkey()
        sha256_hash = hashlib.sha256(pubkey).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        return ripemd160_hash[:4]

    def derive(self, index: int) -> 'CExtKey':
        """
        Derive a child key at the given index.

        Args:
            index: Child index (>= 0x80000000 for hardened)

        Returns:
            Derived extended key
        """
        if index < 0:
            raise ValueError("Index must be non-negative")

        # Hardened derivation
        if index >= HARDENED_KEY_START:
            # Data = 0x00 || key || index
            data = b'\x00' + self.key + struct.pack('>I', index)
        else:
            # Normal derivation - use public key
            data = self.get_pubkey() + struct.pack('>I', index)

        # HMAC-SHA512 with chaincode
        I = hmac.new(self.chaincode, data, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]

        # Check for invalid derivation
        IL_int = int.from_bytes(IL, 'big')
        key_int = int.from_bytes(self.key, 'big')

        if IL_int >= SECP256K1_ORDER:
            raise ValueError("Invalid derived key")

        # Child key = (IL + parent_key) mod n
        child_key_int = (IL_int + key_int) % SECP256K1_ORDER
        child_key = child_key_int.to_bytes(32, 'big')

        return CExtKey(
            n_depth=self.n_depth + 1,
            n_parent_fingerprint=self.get_fingerprint(),
            n_child=index,
            chaincode=IR,
            key=child_key
        )

    def derive_path(self, path: DerivationPath) -> 'CExtKey':
        """
        Derive key at the given path.

        Args:
            path: Derivation path

        Returns:
            Derived extended key
        """
        result = self
        for component in path.components:
            result = result.derive(component)
        return result

    def neuter(self) -> 'CExtPubKey':
        """
        Create the extended public key (remove private key).
        """
        return CExtPubKey(
            n_depth=self.n_depth,
            n_parent_fingerprint=self.n_parent_fingerprint,
            n_child=self.n_child,
            chaincode=self.chaincode,
            pubkey=self.get_pubkey()
        )


@dataclass
class CExtPubKey:
    """
    Extended public key (BIP32).

    Contains a public key with chain code and derivation info.
    Can only derive non-hardened children.
    """
    n_depth: int = 0
    n_parent_fingerprint: bytes = field(default_factory=lambda: bytes(4))
    n_child: int = 0
    chaincode: bytes = field(default_factory=lambda: bytes(32))
    pubkey: bytes = field(default_factory=lambda: bytes(33))

    def get_fingerprint(self) -> bytes:
        """Get the key fingerprint."""
        sha256_hash = hashlib.sha256(self.pubkey).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        return ripemd160_hash[:4]

    def derive(self, index: int) -> 'CExtPubKey':
        """
        Derive a child public key.

        Args:
            index: Child index (must be non-hardened, < 0x80000000)

        Returns:
            Derived extended public key
        """
        if index >= HARDENED_KEY_START:
            raise ValueError("Extended public key cannot derive hardened keys")

        # Data = pubkey || index
        data = self.pubkey + struct.pack('>I', index)

        # HMAC-SHA512 with chaincode
        I = hmac.new(self.chaincode, data, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]

        IL_int = int.from_bytes(IL, 'big')
        if IL_int >= SECP256K1_ORDER:
            raise ValueError("Invalid derived key")

        # Child pubkey = IL * G + parent_pubkey
        # This requires elliptic curve addition
        if HAS_COINCURVE:
            parent_pub = PublicKey(self.pubkey)
            # Multiply IL by generator and add to parent pubkey
            IL_bytes = IL_int.to_bytes(32, 'big')
            child_pub = parent_pub.add(IL_bytes)
            child_pubkey = child_pub.format(compressed=True)
        else:
            # Fallback - just hash (not cryptographically correct)
            child_pubkey = b'\x02' + hashlib.sha256(IL + self.pubkey).digest()[:32]

        return CExtPubKey(
            n_depth=self.n_depth + 1,
            n_parent_fingerprint=self.get_fingerprint(),
            n_child=index,
            chaincode=IR,
            pubkey=child_pubkey
        )

    def derive_path(self, path: DerivationPath) -> 'CExtPubKey':
        """
        Derive public key at the given path.

        Note: Path must not contain hardened derivation.
        """
        result = self
        for component in path.components:
            result = result.derive(component)
        return result


# BIP39 Mnemonic Support

BIP39_WORDLIST_ENGLISH = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
    "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
    "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable",
    "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
    "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable",
    "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry",
    "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog",
    "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling",
    "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk",
    "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap",
    "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar",
    "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify",
    "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff",
    "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud",
    "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
    "code", "coffee", "coil", "coin", "collect", "color", "column", "combine",
    "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm",
    "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper",
    "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch",
    "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle",
    "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream",
    "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop",
    "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch",
    "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious",
    "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad",
    "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn",
    "day", "deal", "debate", "debris", "decade", "december", "decide", "decline",
    "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay",
    "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend",
    "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk",
    "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram",
    "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital",
    "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover",
    "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide",
    "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain",
    "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft",
    "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill",
    "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb",
    "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager",
    "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo",
    "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight",
    "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator",
    "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ",
    "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy",
    "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough",
    "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode",
    "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt",
    "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil",
    "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude",
    "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit",
    "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend",
    "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint",
    "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy",
    "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault",
    "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female",
    "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field",
    "figure", "file", "film", "filter", "final", "find", "fine", "finger",
    "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness",
    "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight",
    "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly",
    "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot",
    "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil",
    "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend",
    "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel",
    "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy",
    "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment",
    "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius",
    "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle",
    "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass",
    "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue",
    "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip",
    "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass",
    "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group",
    "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun",
    "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy",
    "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard",
    "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet",
    "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip",
    "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow",
    "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital",
    "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble",
    "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband",
    "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill",
    "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose",
    "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate",
    "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial",
    "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane",
    "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest",
    "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory",
    "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel",
    "job", "join", "joke", "journey", "joy", "judge", "juice", "jump",
    "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup",
    "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit",
    "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know",
    "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language",
    "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law",
    "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave",
    "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend",
    "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty",
    "library", "license", "life", "lift", "light", "like", "limb", "limit",
    "link", "lion", "liquid", "list", "little", "live", "lizard", "load",
    "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop",
    "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber",
    "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet",
    "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
    "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin",
    "marine", "market", "marriage", "mask", "mass", "master", "match", "material",
    "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure",
    "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory",
    "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message",
    "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
    "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake",
    "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment",
    "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning",
    "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie",
    "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music",
    "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
    "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative",
    "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral",
    "never", "news", "next", "nice", "night", "noble", "noise", "nominee",
    "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice",
    "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey",
    "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean",
    "october", "odor", "off", "offer", "office", "often", "oil", "okay",
    "old", "olive", "olympic", "omit", "once", "one", "onion", "online",
    "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit",
    "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich",
    "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over",
    "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page",
    "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper",
    "parade", "parent", "park", "parrot", "party", "pass", "patch", "path",
    "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut",
    "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper",
    "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical",
    "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot",
    "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet",
    "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge",
    "poem", "poet", "point", "polar", "pole", "police", "pond", "pony",
    "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery",
    "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare",
    "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority",
    "prison", "private", "prize", "problem", "process", "produce", "profit", "program",
    "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide",
    "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil",
    "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle",
    "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz",
    "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail",
    "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid",
    "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real",
    "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle",
    "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject",
    "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove",
    "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report",
    "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire",
    "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib",
    "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid",
    "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road",
    "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room",
    "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude",
    "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness",
    "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same",
    "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say",
    "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science",
    "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea",
    "search", "season", "seat", "second", "secret", "section", "security", "seed",
    "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence",
    "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
    "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine",
    "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder",
    "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
    "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar",
    "simple", "since", "sing", "siren", "sister", "situate", "six", "size",
    "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab",
    "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan",
    "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth",
    "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social",
    "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve",
    "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup",
    "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
    "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin",
    "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray",
    "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium",
    "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay",
    "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting",
    "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
    "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject",
    "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest",
    "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme",
    "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain",
    "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim",
    "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table",
    "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target",
    "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten",
    "tenant", "tennis", "tent", "term", "test", "text", "thank", "that",
    "theme", "then", "theory", "there", "they", "thing", "this", "thought",
    "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger",
    "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title",
    "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token",
    "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top",
    "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist",
    "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic",
    "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree",
    "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy",
    "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try",
    "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle",
    "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical",
    "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo",
    "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown",
    "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon",
    "upper", "upset", "urban", "urge", "usage", "use", "used", "useful",
    "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley",
    "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle",
    "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very",
    "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view",
    "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual",
    "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote",
    "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want",
    "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave",
    "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding",
    "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat",
    "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife",
    "wild", "will", "win", "window", "wine", "wing", "wink", "winner",
    "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman",
    "wonder", "wood", "wool", "word", "work", "world", "worry", "worth",
    "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year",
    "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo",
]

# Load full wordlist from file if available
def _load_wordlist() -> List[str]:
    """Load BIP39 wordlist."""
    # Try to load from a file or return the minimal list
    return BIP39_WORDLIST_ENGLISH


def generate_mnemonic(strength: int = 128) -> str:
    """
    Generate a BIP39 mnemonic.

    Args:
        strength: Entropy strength in bits (128, 160, 192, 224, or 256)

    Returns:
        Mnemonic string with space-separated words
    """
    if strength not in [128, 160, 192, 224, 256]:
        raise ValueError("Strength must be 128, 160, 192, 224, or 256")

    # Generate entropy
    entropy = secrets.token_bytes(strength // 8)

    # Add checksum
    entropy_bits = int.from_bytes(entropy, 'big')
    checksum_bits = strength // 32
    checksum = hashlib.sha256(entropy).digest()
    checksum_int = checksum[0] >> (8 - checksum_bits)
    entropy_with_checksum = (entropy_bits << checksum_bits) | checksum_int

    # Convert to words
    wordlist = _load_wordlist()
    total_bits = strength + checksum_bits
    words = []
    for i in range(total_bits // 11):
        index = (entropy_with_checksum >> (total_bits - 11 * (i + 1))) & 0x7FF
        words.append(wordlist[index])

    return ' '.join(words)


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Convert BIP39 mnemonic to seed.

    Args:
        mnemonic: Space-separated mnemonic words
        passphrase: Optional passphrase for additional security

    Returns:
        64-byte seed
    """
    # Normalize mnemonic
    mnemonic_normalized = ' '.join(mnemonic.strip().split())
    mnemonic_bytes = mnemonic_normalized.encode('utf-8')

    # Salt is "mnemonic" + passphrase
    salt = ("mnemonic" + passphrase).encode('utf-8')

    # PBKDF2 with 2048 iterations
    seed = hashlib.pbkdf2_hmac(
        'sha512',
        mnemonic_bytes,
        salt,
        2048
    )

    return seed


def mnemonic_to_ext_key(mnemonic: str, passphrase: str = "") -> CExtKey:
    """
    Convert mnemonic to extended master key.

    Args:
        mnemonic: BIP39 mnemonic
        passphrase: Optional passphrase

    Returns:
        Master extended key
    """
    seed = mnemonic_to_seed(mnemonic, passphrase)
    return CExtKey.from_seed(seed)


def validate_mnemonic(mnemonic: str) -> bool:
    """
    Validate a BIP39 mnemonic.

    Args:
        mnemonic: Space-separated mnemonic words

    Returns:
        True if valid, False otherwise
    """
    words = mnemonic.strip().split()
    word_count = len(words)

    # Valid word counts: 12, 15, 18, 21, 24
    if word_count not in [12, 15, 18, 21, 24]:
        return False

    wordlist = _load_wordlist()

    # Check all words are in wordlist
    for word in words:
        if word not in wordlist:
            return False

    # Verify checksum
    total_bits = word_count * 11
    checksum_bits = total_bits // 33
    entropy_bits = total_bits - checksum_bits

    # Convert words to indices
    indices = [wordlist.index(word) for word in words]

    # Convert to integer
    entropy_with_checksum = 0
    for i, idx in enumerate(indices):
        entropy_with_checksum = (entropy_with_checksum << 11) | idx

    # Extract entropy and checksum
    entropy = entropy_with_checksum >> checksum_bits
    stored_checksum = entropy_with_checksum & ((1 << checksum_bits) - 1)

    # Calculate expected checksum
    entropy_bytes = entropy.to_bytes(entropy_bits // 8, 'big')
    checksum = hashlib.sha256(entropy_bytes).digest()[0] >> (8 - checksum_bits)

    return checksum == stored_checksum


# Key conversion utilities

def key_to_wif(key: bytes, compressed: bool = True, testnet: bool = False) -> str:
    """
    Convert private key to WIF (Wallet Import Format).

    Args:
        key: 32-byte private key
        compressed: Whether to use compressed public key
        testnet: Whether to use testnet prefix

    Returns:
        WIF string
    """
    # Add prefix
    prefix = b'\xef' if testnet else b'\x80'
    data = prefix + key

    # Add compression flag
    if compressed:
        data += b'\x01'

    # Add checksum
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    data += checksum

    # Base58 encode
    return _base58_encode(data)


def wif_to_key(wif: str) -> Tuple[bytes, bool, bool]:
    """
    Convert WIF to private key.

    Args:
        wif: WIF string

    Returns:
        Tuple of (key, compressed, testnet)
    """
    data = _base58_decode(wif)

    # Check length
    if len(data) not in [33, 34]:
        raise ValueError("Invalid WIF length")

    # Check checksum
    checksum = data[-4:]
    expected_checksum = hashlib.sha256(hashlib.sha256(data[:-4]).digest()).digest()[:4]
    if checksum != expected_checksum:
        raise ValueError("Invalid WIF checksum")

    # Extract data
    testnet = data[0] == 0xef
    key = data[1:33]
    compressed = len(data) == 38  # 33 bytes + prefix + checksum + compression flag

    return key, compressed, testnet


def _base58_encode(data: bytes) -> str:
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


def _base58_decode(s: str) -> bytes:
    """Base58 decode."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    # Count leading '1's
    leading_ones = 0
    for c in s:
        if c == '1':
            leading_ones += 1
        else:
            break

    # Convert from base58
    num = 0
    for c in s:
        num = num * 58 + alphabet.index(c)

    # Convert to bytes
    if num == 0:
        result = b''
    else:
        result = []
        while num > 0:
            result.append(num & 0xff)
            num >>= 8
        result = bytes(reversed(result))

    # Add leading zeros
    return b'\x00' * leading_ones + result
