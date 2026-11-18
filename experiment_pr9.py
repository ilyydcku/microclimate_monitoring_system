"""Серии A и B, CSV из 45 наблюдений, без вывода ключей."""
import csv
import hmac
import sys
from base64 import b64decode, b64encode
from hashlib import sha256
from secrets import token_bytes

from app.crypto_fields import NONCE_SIZE, ProtectedFieldError, decrypt_field, encrypt_field, load_data_key, stored_length

SAMPLE = "Учебная заметка № 1"
EXPECTED = {"A0": "equal", "A1": "different", "A2": "equal", "A3": "accepted", "A4": "rejected", "B0": "restored", **{f"B{i}": "rejected" for i in range(1, 6)}}


def observe_hash_and_mac(writer):
    mac_key = token_bytes(32)
    for trial, source in enumerate((b"quota=10", b"quota=20", b"quota=30"), 1):
        modified = source[:-1] + b"1"
        reference = sha256(source).digest()
        changed = sha256(modified).digest()
        for series, digest, expected in (("A0", sha256(source).digest(), reference),
                ("A1", changed, reference), ("A2", changed, sha256(modified).digest())):
            writer.writerow((series, trial, "equal" if digest == expected else "different", digest.hex(), "", ""))
        tag = hmac.digest(mac_key, source, "sha256")
        for series, candidate in (("A3", source), ("A4", modified)):
            valid = hmac.compare_digest(tag, hmac.digest(mac_key, candidate, "sha256"))
            writer.writerow((series, trial, "accepted" if valid else "rejected", "", "", ""))


def change_one_byte(stored, offset):
    header, payload = stored.rsplit(".", 1)
    data = bytearray(b64decode(payload))
    data[offset] ^= 1
    return f"{header}.{b64encode(data).decode('ascii')}"


def observe_read(stored, record_id, key, expected):
    try:
        plaintext = decrypt_field(stored, record_id, key)
    except ProtectedFieldError:
        return "rejected"
    return "restored" if plaintext == expected else "wrong_value"


def observe_encryption(writer, key):
    record_id = "R-001"
    other_key = bytes([key[0] ^ 1]) + key[1:]
    for trial in range(1, 6):
        stored = encrypt_field(SAMPLE, record_id, key)
        nonce = b64decode(stored.rsplit(".", 1)[1])[:NONCE_SIZE]
        cases = (("B0", stored, record_id, key),
                 ("B1", change_one_byte(stored, NONCE_SIZE), record_id, key),
                 ("B2", stored, "R-002", key),
                 ("B3", stored, record_id, other_key),
                 ("B4", change_one_byte(stored, 0), record_id, key),
                 ("B5", change_one_byte(stored, -1), record_id, key))
        for series, value, rid, active_key in cases:
            result = observe_read(value, rid, active_key, SAMPLE)
            detail = (nonce.hex(), len(SAMPLE.encode("utf-8")), len(stored)) if series == "B0" else ("", "", "")
            writer.writerow((series, trial, result, *detail))


def profile_p1(key):
    print("Value | characters | UTF-8 bytes | measured | calculated")
    for value in ("A", "Я", "…"):
        size = len(value.encode("utf-8"))
        stored = encrypt_field(value, "R-001", key)
        assert decrypt_field(stored, "R-001", key) == value
        print(f"{value} | {len(value)} | {size} | {len(stored)} | {stored_length(size)}")
        assert len(stored) == stored_length(size)


def main():
    key = load_data_key()
    if sys.argv[1:] == ["--profile"]:
        profile_p1(key)
        return
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(("series", "trial", "outcome", "detail", "plain_bytes", "stored_chars"))
    observe_hash_and_mac(writer)
    observe_encryption(writer, key)


if __name__ == "__main__":
    main()
