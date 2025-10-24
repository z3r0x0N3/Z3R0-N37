
import hashlib

from cryptography.fernet import Fernet
import pgpy


# Hashing -------------------------------------------------------------------
def hash_data(data: bytes, algorithm: str = "sha512") -> bytes:
    """Hashes data using the specified algorithm."""
    h = hashlib.new(algorithm)
    h.update(data)
    return h.digest()


# AES Encryption/Decryption -------------------------------------------------
def generate_aes_key() -> bytes:
    """Generates an AES key."""
    return Fernet.generate_key()


def encrypt_aes(data: bytes, key: bytes) -> bytes:
    """Encrypts data using AES."""
    f = Fernet(key)
    return f.encrypt(data)


def decrypt_aes(token: bytes, key: bytes) -> bytes:
    """Decrypts data using AES."""
    f = Fernet(key)
    return f.decrypt(token)


# PGP Encryption/Decryption -------------------------------------------------
def generate_pgp_key(name: str, email: str) -> tuple[pgpy.PGPKey, pgpy.PGPKey]:
    """Generates a PGP key pair."""
    key = pgpy.PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new(name, email=email)
    key.add_uid(
        uid,
        usage={
            pgpy.constants.KeyFlags.Sign,
            pgpy.constants.KeyFlags.EncryptCommunications,
            pgpy.constants.KeyFlags.EncryptStorage,
        },
        hashes=[pgpy.constants.HashAlgorithm.SHA512],
        ciphers=[pgpy.constants.SymmetricKeyAlgorithm.AES256],
        compression=[pgpy.constants.CompressionAlgorithm.ZLIB],
    )
    return key, key.pubkey


def encrypt_pgp(data: bytes, pub_key: pgpy.PGPKey) -> bytes:
    """Encrypts data using a PGP public key."""
    message = pgpy.PGPMessage.new(data)
    encrypted_message = pub_key.encrypt(message, compression=pgpy.constants.CompressionAlgorithm.ZLIB)
    return bytes(encrypted_message)


def decrypt_pgp(data: bytes, priv_key: pgpy.PGPKey) -> bytes:
    """Decrypts data using a PGP private key."""
    encrypted_message = pgpy.PGPMessage.from_blob(data)
    decrypted_message = priv_key.decrypt(encrypted_message)
    return decrypted_message.message


# Digital shift cipher ------------------------------------------------------
def digital_shift_cipher(data: bytes, shift: int) -> bytes:
    """Applies a reversible byte-wise shift cipher."""
    if shift == 0:
        return data
    # Constrain shift to a single byte range to avoid huge loops
    effective_shift = shift % 256
    return bytes((byte + effective_shift) % 256 for byte in data)


def reverse_digital_shift_cipher(data: bytes, shift: int) -> bytes:
    """Reverse operation for digital_shift_cipher."""
    if shift == 0:
        return data
    effective_shift = shift % 256
    return bytes((byte - effective_shift) % 256 for byte in data)
