from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_AES_BLOCK_SIZE = 16


def _pkcs7_pad(data: bytes, *, block_size: int = _AES_BLOCK_SIZE) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("invalid block_size")
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(padded: bytes, *, block_size: int = _AES_BLOCK_SIZE) -> bytes:
    if not padded:
        raise ValueError("invalid PKCS7 padding (empty)")
    pad_len = padded[-1]
    if pad_len <= 0 or pad_len > block_size:
        raise ValueError("invalid PKCS7 padding length")
    if pad_len > len(padded):
        raise ValueError("invalid PKCS7 padding length")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS7 padding bytes")
    return padded[:-pad_len]


def aes_encrypt_gcm(plaintext: bytes, *, key: bytes, iv: bytes, aad: bytes) -> bytes:
    if len(iv) != 12:
        raise ValueError("AES-GCM IV must be 12 bytes")
    return AESGCM(key).encrypt(iv, plaintext, aad)


def aes_decrypt_gcm(ciphertext_and_tag: bytes, *, key: bytes, iv: bytes, aad: bytes) -> bytes:
    if len(iv) != 12:
        raise ValueError("AES-GCM IV must be 12 bytes")
    return AESGCM(key).decrypt(iv, ciphertext_and_tag, aad)


def aes_encrypt_ctr(plaintext: bytes, *, key: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_decrypt_ctr(ciphertext: bytes, *, key: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def aes_encrypt_cbc_pkcs7(plaintext: bytes, *, key: bytes, iv: bytes) -> bytes:
    """
    AES-256-CBC encryption with PKCS7 padding (Signal/WhatsApp uses this for message encryption).
    """

    if len(iv) != _AES_BLOCK_SIZE:
        raise ValueError("AES-CBC IV must be 16 bytes")
    padded = _pkcs7_pad(plaintext)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt_cbc_pkcs7(ciphertext: bytes, *, key: bytes, iv: bytes) -> bytes:
    """
    AES-256-CBC decryption with PKCS7 unpadding (Signal/WhatsApp uses this for message decryption).
    """

    if len(iv) != _AES_BLOCK_SIZE:
        raise ValueError("AES-CBC IV must be 16 bytes")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return _pkcs7_unpad(padded)
