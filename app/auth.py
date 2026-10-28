"""Учебная аутентификация v0.7 по практической работе № 7."""

import hashlib
import hmac
import re
import secrets
import sqlite3
import time
import unicodedata
from contextlib import closing
from pathlib import Path


class AuthService:
    """Регистрация, парольный вход, сеансы и восстановление доступа."""

    MAX_FAILS = 5
    BLOCK_SECONDS = 60
    IDLE_SECONDS = 900
    ABSOLUTE_SECONDS = 3600

    # Демонстрационный список, не полноценная база скомпрометированных паролей.
    WEAK = {
        "password123456789",
        "123456789012345",
        "qwertyqwertyqwerty",
    }
    TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")

    def __init__(self, database: Path, *, clock=time.time, rounds=600_000):
        if type(rounds) is not int or not 1_000 <= rounds <= 2_000_000:
            raise ValueError("Некорректная стоимость PBKDF2")
        self.database = Path(database)
        self.clock = clock
        self.rounds = rounds

    @staticmethod
    def _login(login: str) -> str:
        """Проверить и нормализовать логин."""
        if type(login) is not str:
            raise ValueError("Неверный логин")
        value = login.casefold()
        if re.fullmatch(r"[a-z][a-z0-9_]{2,31}", value) is None:
            raise ValueError("Неверный логин")
        return value

    @classmethod
    def _password(cls, password: str, *, new: bool = False) -> bytes:
        """Привести пароль к NFC, не удаляя пробелы и не меняя регистр."""
        if type(password) is not str:
            raise ValueError("Ожидается пароль-строка")
        normalized = unicodedata.normalize("NFC", password)
        if not 1 <= len(normalized) <= 128:
            raise ValueError("Недопустимая длина пароля")
        try:
            value = normalized.encode("utf-8")
        except UnicodeError as exc:
            raise ValueError("Некорректный Unicode") from exc
        if len(value) > 1024:
            raise ValueError("Превышен размер пароля")
        if new and (len(normalized) < 15 or normalized.casefold() in cls.WEAK):
            raise ValueError("Пароль не соответствует политике")
        return value

    @staticmethod
    def _pbkdf2(value: bytes, salt: bytes, rounds: int) -> bytes:
        """Получить проверочное значение пароля без хранения исходной строки."""
        return hashlib.pbkdf2_hmac("sha256", value, salt, rounds, dklen=32)

    @classmethod
    def _token_hash(cls, token: str):
        """Проверять формат непрозрачного токена перед вычислением SHA-256."""
        if type(token) is not str or cls.TOKEN_RE.fullmatch(token) is None:
            return None
        return hashlib.sha256(token.encode("ascii")).digest()

    def _connect(self):
        """Открыть SQLite-соединение с проверкой внешних ключей."""
        conn = sqlite3.connect(self.database, timeout=5)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self):
        """Создать таблицы пользователей и серверных сеансов."""
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn, conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    login TEXT NOT NULL UNIQUE,
                    salt BLOB NOT NULL,
                    rounds INTEGER NOT NULL,
                    password_hash BLOB NOT NULL,
                    recovery_hash BLOB NOT NULL,
                    failures INTEGER NOT NULL DEFAULT 0,
                    blocked_until REAL NOT NULL DEFAULT 0,
                    active INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash BLOB PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created REAL NOT NULL,
                    last_seen REAL NOT NULL
                );
                """
            )

    def register(self, login: str, password: str):
        """Зарегистрировать пользователя; вернуть ID и резервный код один раз."""
        username = self._login(login)
        pw = self._password(password, new=True)
        salt = secrets.token_bytes(16)
        recovery = secrets.token_urlsafe(32)
        with closing(self._connect()) as conn, conn:
            result = conn.execute(
                """
                INSERT INTO users (login, salt, rounds, password_hash, recovery_hash)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    username,
                    salt,
                    self.rounds,
                    self._pbkdf2(pw, salt, self.rounds),
                    self._token_hash(recovery),
                ),
            )
            return int(result.lastrowid), recovery

    def login(self, login: str, password: str):
        """Проверить пароль и ограничение попыток; вернуть токен или None."""
        try:
            username = self._login(login)
            value = self._password(password)
        except ValueError:
            return None

        now = self.clock()
        with closing(self._connect()) as conn, conn:
            # BEGIN IMMEDIATE защищает счётчик неудач от гонки операций SQLite.
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM users WHERE login=?", (username,)).fetchone()
            # Подбор неизвестного логина также выполняет одну KDF-операцию.
            salt = row["salt"] if row else b"0" * 16
            rounds = row["rounds"] if row else self.rounds
            candidate = self._pbkdf2(value, salt, rounds)
            expected = row["password_hash"] if row else bytes(32)
            valid = hmac.compare_digest(candidate, expected)

            if row is None or not row["active"] or now < row["blocked_until"]:
                return None

            if not valid:
                failures = row["failures"] + 1
                blocked = now + self.BLOCK_SECONDS if failures >= self.MAX_FAILS else 0
                if blocked:
                    failures = 0
                conn.execute(
                    "UPDATE users SET failures=?, blocked_until=? WHERE id=?",
                    (failures, blocked, row["id"]),
                )
                return None

            conn.execute(
                "UPDATE users SET failures=0, blocked_until=0 WHERE id=?",
                (row["id"],),
            )
            token = secrets.token_urlsafe(32)
            conn.execute(
                """
                INSERT INTO sessions (token_hash, user_id, created, last_seen)
                VALUES (?, ?, ?, ?)
                """,
                (self._token_hash(token), row["id"], now, now),
            )
            return token

    def resolve(self, token: str):
        """Проверить серверный сеанс и вернуть user_id либо None."""
        key = self._token_hash(token)
        if key is None:
            return None
        now = self.clock()
        with closing(self._connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT s.user_id, s.created, s.last_seen, u.active
                FROM sessions AS s
                JOIN users AS u ON u.id=s.user_id
                WHERE s.token_hash=?
                """,
                (key,),
            ).fetchone()
            if row is None:
                return None
            if (
                not row["active"]
                or now - row["created"] >= self.ABSOLUTE_SECONDS
                or now - row["last_seen"] >= self.IDLE_SECONDS
            ):
                conn.execute("DELETE FROM sessions WHERE token_hash=?", (key,))
                return None

            conn.execute(
                "UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, key)
            )
            return row["user_id"]

    def logout(self, token: str):
        """Отозвать токен на сервере (клиент также удаляет локальную копию)."""
        key = self._token_hash(token)
        if key is None:
            return
        with closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (key,))

    def reset_password(self, login: str, code: str, new_password: str):
        """Погасить одноразовый код, сменить пароль и отозвать все сеансы."""
        try:
            username = self._login(login)
            new_value = self._password(new_password, new=True)
        except ValueError:
            return None
        code_hash = self._token_hash(code)
        if code_hash is None:
            return None

        with closing(self._connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT id, recovery_hash FROM users WHERE login=? AND active=1",
                (username,),
            ).fetchone()
            saved = row["recovery_hash"] if row else bytes(32)
            if not hmac.compare_digest(saved, code_hash) or row is None:
                return None

            new_salt = secrets.token_bytes(16)
            next_code = secrets.token_urlsafe(32)
            result = conn.execute(
                """
                UPDATE users
                SET salt=?, rounds=?, password_hash=?, recovery_hash=?,
                    failures=0, blocked_until=0
                WHERE id=? AND recovery_hash=?
                """,
                (
                    new_salt,
                    self.rounds,
                    self._pbkdf2(new_value, new_salt, self.rounds),
                    self._token_hash(next_code),
                    row["id"],
                    code_hash,
                ),
            )
            if result.rowcount != 1:
                return None
            conn.execute("DELETE FROM sessions WHERE user_id=?", (row["id"],))
            return next_code
