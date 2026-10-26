"""Envelope-Verschlüsselung für Dokumente und Passwort-Hashing.

Jedes Dokument bekommt einen eigenen zufälligen Data Encryption Key (DEK).
Der DEK wird mit dem Master-Key (KEK) per AES-256-GCM "gewrappt" und in der
Datenbank gespeichert. Die Dokumentdatei selbst ist mit dem DEK verschlüsselt.
Die Dokument-ID dient jeweils als Associated Data, damit verschlüsselte Blobs
und Schlüssel nicht zwischen Dokumenten vertauscht werden können.

Eine Rotation des Master-Keys erfordert damit nur ein Neu-Wrappen der DEKs,
nicht das Neu-Verschlüsseln aller Dateien.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
KEY_SIZE = 32


class DecryptionError(Exception):
    pass


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=KEY_SIZE * 8)


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < NONCE_SIZE + 16:
        raise DecryptionError("Ciphertext zu kurz")
    try:
        return AESGCM(key).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], aad)
    except Exception as exc:  # InvalidTag
        raise DecryptionError("Entschlüsselung fehlgeschlagen") from exc


def wrap_key(master_key: bytes, dek: bytes, doc_id: str) -> bytes:
    return encrypt(master_key, dek, b"dek:" + doc_id.encode())


def unwrap_key(master_key: bytes, wrapped: bytes, doc_id: str) -> bytes:
    return decrypt(master_key, wrapped, b"dek:" + doc_id.encode())


# --- Passwörter -------------------------------------------------------------

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    digest = hashlib.scrypt(
        password.encode(), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p)
    )
    return hmac.compare_digest(digest, bytes.fromhex(digest_hex))
