"""Защита конфиденциального поля заявок (практическая работа № 9)."""
import json
import os
import re
from base64 import b64decode, b64encode
from secrets import token_bytes

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_VAR = "PR9_DATA_KEY_HEX"
HEADER = "v1.lab-k1"
FIELD_SCOPE = "requests.private_note"
NONCE_SIZE = 12
TAG_SIZE = 16


class ProtectedFieldError(ValueError):
    """Единый отказ при ошибке защищенного представления."""


def load_data_key() -> bytes:
    value = os.environ.get(KEY_VAR, "")
    if re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise RuntimeError(f"{KEY_VAR}: требуется ключ из 32 байтов в hex")
    return bytes.fromhex(value)


def associated_data(record_id: str) -> bytes:
    return json.dumps([HEADER, FIELD_SCOPE, record_id], separators=(",", ":")).encode("ascii")


def encrypt_field(text: str, record_id: str, key: bytes) -> str:
    if type(key) is not bytes or len(key) != 32:
        raise ValueError("Требуется 32-байтовый ключ AES")
    nonce = token_bytes(NONCE_SIZE)
    sealed = AESGCM(key).encrypt(nonce, text.encode("utf-8"), associated_data(record_id))
    return f"{HEADER}.{b64encode(nonce + sealed).decode('ascii')}"


def decrypt_field(stored: str, record_id: str, key: bytes) -> str:
    error = "Не удалось прочитать защищенное поле"
    if type(stored) is not str or type(key) is not bytes or len(key) != 32:
        raise ProtectedFieldError(error)
    header, _, payload = stored.rpartition(".")
    if header != HEADER:
        raise ProtectedFieldError(error)
    try:
        data = b64decode(payload, validate=True)
        if len(data) < NONCE_SIZE + TAG_SIZE:
            raise ValueError
        if b64encode(data).decode("ascii") != payload:
            raise ValueError
        plaintext = AESGCM(key).decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], associated_data(record_id))
        return plaintext.decode("utf-8")
    except (InvalidTag, ValueError):
        raise ProtectedFieldError(error) from None


def stored_length(plain_bytes: int) -> int:
    return len(HEADER) + 1 + 4 * ((plain_bytes + NONCE_SIZE + TAG_SIZE + 2) // 3)
