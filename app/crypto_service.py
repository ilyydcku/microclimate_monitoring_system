"""Интеграция AES-GCM с реальной авторизацией заявок v0.8."""
import json
import sqlite3
import unicodedata

from app.authorization import AccessDenied, AccessService
from app.crypto_fields import ProtectedFieldError, decrypt_field, encrypt_field, load_data_key
from app.validation import load_request

MAX_NOTE_BYTES = 2000


def initialize_crypto(db: sqlite3.Connection) -> None:
    """Аддитивная миграция после initialize_authorization()."""
    db.execute("BEGIN IMMEDIATE")
    try:
        columns = {row[1] for row in db.execute("PRAGMA table_info(requests)")}
        if not {"id", "owner_id", "department_id", "status"} <= columns:
            raise RuntimeError("Необходима схема v0.8")
        if "private_note" not in columns:
            db.execute("ALTER TABLE requests ADD COLUMN private_note TEXT")
        db.commit()
    except Exception:
        db.rollback()
        raise


def validate_note(value: str) -> str:
    if type(value) is not str:
        raise ValueError("Некорректная заметка")
    value = unicodedata.normalize("NFC", value)
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise ValueError("Некорректная заметка") from None
    if not value.strip() or size > MAX_NOTE_BYTES or any(
        unicodedata.category(char).startswith("C") and char not in "\n\r\t" for char in value
    ):
        raise ValueError("Некорректная заметка")
    return value


class ProtectedRequestService(AccessService):
    """Расширение v0.8: прежние права и сеансы, отдельное защищенное поле."""

    def __init__(self, db, resolve_session):
        self._data_key = load_data_key()
        super().__init__(db, resolve_session)

    def create_protected_request(self, token: str, title: str, private_note: str) -> int:
        with self._operation(token, "request.create") as (user, db):
            note = validate_note(private_note)
            request = load_request(json.dumps({
                "title": title,
                "description": "Учебная заявка о состоянии оборудования микроклимата.",
                "category": "other",
                "priority": 3,
            }, ensure_ascii=False).encode("utf-8"))
            cursor = db.execute("""
                INSERT INTO requests (title, description, category, priority,
                    owner_id, department_id, status)
                VALUES (?, ?, ?, ?, ?, ?, 'new')
            """, (request.title, request.description, request.category,
                  request.priority, user["id"], user["department_id"]))
            record_id = int(cursor.lastrowid)
            protected = encrypt_field(note, str(record_id), self._data_key)
            db.execute("UPDATE requests SET private_note = ? WHERE id = ?", (protected, record_id))
            return record_id

    def read_private_note(self, token: str, request_id: int) -> str | None:
        with self._operation(token, "request.read") as (user, db):
            self._check_id(request_id)
            row = db.execute("SELECT id, owner_id, private_note FROM requests WHERE id = ?",
                             (request_id,)).fetchone()
            if row is None or (user["role"] == "user" and row["owner_id"] != user["id"]):
                raise AccessDenied("Операция недоступна")
            # Проверка прав предшествует расшифрованию; ID получен из БД.
            if row["private_note"] is None:
                return None
            return decrypt_field(row["private_note"], str(row["id"]), self._data_key)
