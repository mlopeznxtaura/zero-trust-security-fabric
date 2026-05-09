"""
Google Tink + libsodium application-level encryption.
AEAD encryption, key rotation, hybrid encryption, and digital signatures.
SDKs: tink, pynacl (libsodium), cryptography
"""
import os
import base64
import json
from typing import Optional, Dict, Any, Tuple
from pathlib import Path

try:
    import tink
    from tink import aead, daead, signature, hybrid, mac
    from tink import cleartext_keyset_handle
    from tink.integration import awskms, gcpkms
    TINK_AVAILABLE = True
except ImportError:
    TINK_AVAILABLE = False
    print("Warning: tink not available. Install: pip install tink")

try:
    import nacl.secret
    import nacl.public
    import nacl.signing
    import nacl.utils
    import nacl.encoding
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False
    print("Warning: pynacl not available. Install: pip install pynacl")

from cryptography.hazmat.primitives import hashes, hmac as py_hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import secrets


class TinkCryptoService:
    """
    Tink-based encryption service.
    AEAD encryption with automatic key rotation and keyset management.
    """

    def __init__(self, keyset_path: Optional[str] = None):
        if not TINK_AVAILABLE:
            raise ImportError("tink required. Install: pip install tink")
        aead.register()
        signature.register()
        hybrid.register()
        mac.register()

        self.keyset_path = keyset_path
        if keyset_path and Path(keyset_path).exists():
            self._handle = self._load_keyset(keyset_path)
        else:
            self._handle = self._generate_keyset()
            if keyset_path:
                self._save_keyset(keyset_path)

        self._aead = self._handle.primitive(aead.Aead)
        print(f"[Tink] AEAD service ready")

    def _generate_keyset(self):
        return tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)

    def _load_keyset(self, path: str):
        with open(path, "r") as f:
            return cleartext_keyset_handle.read(tink.JsonKeysetReader(f.read()))

    def _save_keyset(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        writer = tink.JsonKeysetWriter(open(path, "w"))
        cleartext_keyset_handle.write(self._handle, writer)

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        """Encrypt with AES-256-GCM. associated_data is authenticated but not encrypted."""
        return self._aead.encrypt(plaintext, associated_data)

    def decrypt(self, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        """Decrypt and verify associated_data."""
        return self._aead.decrypt(ciphertext, associated_data)

    def encrypt_str(self, plaintext: str, context: str = "") -> str:
        """Encrypt a string and return base64-encoded ciphertext."""
        ct = self.encrypt(plaintext.encode(), context.encode())
        return base64.b64encode(ct).decode()

    def decrypt_str(self, ciphertext_b64: str, context: str = "") -> str:
        """Decrypt a base64-encoded ciphertext string."""
        ct = base64.b64decode(ciphertext_b64)
        return self.decrypt(ct, context.encode()).decode()

    def rotate_key(self):
        """Add a new primary key (old keys still decrypt existing ciphertexts)."""
        manager = tink.KeysetManager(self._handle)
        manager.rotate(aead.aead_key_templates.AES256_GCM)
        self._handle = manager.handle()
        self._aead = self._handle.primitive(aead.Aead)
        print("[Tink] Key rotated — new primary key added")

    def mac_compute(self, data: bytes) -> bytes:
        """Compute a MAC for data integrity verification."""
        mac_handle = tink.new_keyset_handle(mac.mac_key_templates.HMAC_SHA256_128BITTAG)
        mac_primitive = mac_handle.primitive(mac.Mac)
        return mac_primitive.compute_mac(data)


class SodiumCrypto:
    """
    libsodium wrapper via PyNaCl.
    Symmetric secret box, asymmetric public key box, digital signatures.
    """

    def __init__(self):
        if not NACL_AVAILABLE:
            raise ImportError("pynacl required. Install: pip install pynacl")

    def generate_secret_key(self) -> bytes:
        """Generate a 32-byte symmetric key."""
        return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    def symmetric_encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """Encrypt with XSalsa20-Poly1305 (NaCl SecretBox)."""
        box = nacl.secret.SecretBox(key)
        return bytes(box.encrypt(plaintext))

    def symmetric_decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        box = nacl.secret.SecretBox(key)
        return bytes(box.decrypt(ciphertext))

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Curve25519 keypair (private, public)."""
        private_key = nacl.public.PrivateKey.generate()
        return bytes(private_key), bytes(private_key.public_key)

    def asymmetric_encrypt(self, recipient_public: bytes, plaintext: bytes) -> bytes:
        """Seal a message to a recipient (Box encryption, ephemeral sender key)."""
        pub = nacl.public.PublicKey(recipient_public)
        sealed = nacl.public.SealedBox(pub)
        return bytes(sealed.encrypt(plaintext))

    def asymmetric_decrypt(self, private_key: bytes, ciphertext: bytes) -> bytes:
        priv = nacl.public.PrivateKey(private_key)
        sealed = nacl.public.SealedBox(priv)
        return bytes(sealed.decrypt(ciphertext))

    def sign(self, signing_key: bytes, message: bytes) -> bytes:
        """Sign a message with Ed25519."""
        sk = nacl.signing.SigningKey(signing_key)
        return bytes(sk.sign(message))

    def verify(self, verify_key: bytes, signed_message: bytes) -> bytes:
        """Verify and return the original message."""
        vk = nacl.signing.VerifyKey(verify_key)
        return bytes(vk.verify(signed_message))

    def generate_signing_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Ed25519 signing keypair (signing_key, verify_key)."""
        sk = nacl.signing.SigningKey.generate()
        return bytes(sk), bytes(sk.verify_key)


class PythonCryptoService:
    """
    Python cryptography library wrappers.
    RSA, ECDSA, AES-GCM without external dependencies beyond cryptography.
    """

    def generate_rsa_keypair(self, key_size: int = 4096) -> Tuple[bytes, bytes]:
        """Generate RSA keypair. Returns (private_pem, public_pem)."""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem

    def aes_gcm_encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> Dict[str, bytes]:
        """AES-256-GCM encryption. Returns {nonce, ciphertext, tag} as a bundle."""
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, aad)
        return {"nonce": nonce, "ciphertext": ct[:-16], "tag": ct[-16:], "aad": aad}

    def aes_gcm_decrypt(self, key: bytes, bundle: Dict[str, bytes]) -> bytes:
        nonce = bundle["nonce"]
        ct_with_tag = bundle["ciphertext"] + bundle["tag"]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct_with_tag, bundle.get("aad", b""))

    def derive_key(self, password: str, salt: Optional[bytes] = None, length: int = 32) -> Tuple[bytes, bytes]:
        """Derive an AES key from a password using PBKDF2-HMAC-SHA256."""
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        salt = salt or secrets.token_bytes(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length,
                          salt=salt, iterations=600_000, backend=default_backend())
        key = kdf.derive(password.encode())
        return key, salt

    def hmac_sign(self, key: bytes, data: bytes) -> bytes:
        h = py_hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()

    def hmac_verify(self, key: bytes, data: bytes, signature: bytes) -> bool:
        h = py_hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        try:
            h.verify(signature)
            return True
        except Exception:
            return False
