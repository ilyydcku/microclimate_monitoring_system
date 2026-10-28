"""Параметризованные операции с SQLite для проверенных JSON-заявок."""

import re
import sqlite3
from contextlib import closing
from pathlib import Path

from app.validation import ValidatedRequest


class RequestRepository:
    """Слой доступа к SQLite без включения входных данных в SQL-код."""

    SORT = {
        "newest": "id DESC",
        "priority": "priority DESC, id DESC",
    }
    CATEGORIES = {"network", "software", "access", "other"}

    def __init__(self, database: Path):
        self.database = Path(database)

    def connect(self):
        return sqlite3.connect(self.database, timeout=5)

    def initialize(self):
        """Создать таблицу с ограничениями целостности."""

        self.database.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as conn, conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY,
                    title TEXT NOT NULL
                        CHECK(length(title) BETWEEN 5 AND 100),
                    description TEXT NOT NULL
                        CHECK(length(description) BETWEEN 20 AND 2000),
                    category TEXT NOT NULL
                        CHECK(category IN ('network', 'software', 'access', 'other')),
                    priority INTEGER NOT NULL
                        CHECK(typeof(priority) = 'integer' AND priority BETWEEN 1 AND 5),
                    reporter_ip TEXT,
                    attachment_key TEXT
                        CHECK(attachment_key IS NULL OR
                              attachment_key IN ('log', 'report', 'screenshot')),
                    file_id TEXT UNIQUE,
                    CHECK (
                        (attachment_key IS NULL AND file_id IS NULL)
                        OR (attachment_key IS NOT NULL AND length(file_id) = 32)
                    )
                )
                """
            )

    def add(self, request: ValidatedRequest, file_id: str | None = None) -> int:
        """Добавить только предварительно проверенную заявку."""

        if not isinstance(request, ValidatedRequest):
            raise TypeError("Нужен объект ValidatedRequest")
        if (request.attachment_key is None) != (file_id is None):
            raise ValueError("Несогласованное вложение")
        if file_id is not None and (
            type(file_id) is not str
            or re.fullmatch(r"[0-9a-f]{32}", file_id) is None
        ):
            raise ValueError("Некорректный file_id")

        with closing(self.connect()) as conn, conn:
            cursor = conn.execute(
                """
                INSERT INTO requests (
                    title, description, category, priority,
                    reporter_ip, attachment_key, file_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.title,
                    request.description,
                    request.category,
                    request.priority,
                    request.reporter_ip,
                    request.attachment_key,
                    file_id,
                ),
            )
            return int(cursor.lastrowid)

    def get(self, request_id: int) -> dict | None:
        """Вернуть запись по числовому идентификатору."""

        if type(request_id) is not int or request_id < 1:
            raise ValueError("Неверный ID")
        with closing(self.connect()) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM requests WHERE id = ?", (request_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_category(
        self, category: str, sort: str = "newest", limit: int = 20
    ) -> list[dict]:
        """Выбрать категорию; имя сортировки берётся только из allowlist."""

        if type(category) is not str or category not in self.CATEGORIES:
            raise ValueError("Неверная категория")
        if type(sort) is not str or sort not in self.SORT:
            raise ValueError("Недопустимая сортировка")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Неверный лимит")

        order = self.SORT[sort]
        with closing(self.connect()) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"""
                SELECT * FROM requests
                WHERE category = ?
                ORDER BY {order}
                LIMIT ?
                """,
                (category, limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def set_priority(self, request_id: int, priority: int) -> bool:
        """Изменить приоритет в диапазоне 1-5."""

        if (
            type(request_id) is not int
            or request_id < 1
            or type(priority) is not int
            or not 1 <= priority <= 5
        ):
            raise ValueError("Неверный аргумент")
        with closing(self.connect()) as conn, conn:
            result = conn.execute(
                "UPDATE requests SET priority = ? WHERE id = ?",
                (priority, request_id),
            )
            return result.rowcount == 1

    def delete_unattached(self, request_id: int) -> bool:
        """Удалить только запись без вложения, удерживая блокировку записи."""

        if type(request_id) is not int or request_id < 1:
            raise ValueError("Неверный ID")
        with closing(self.connect()) as conn, conn:
            # Не допускаем изменения записи между проверкой и удалением.
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT file_id FROM requests WHERE id = ?", (request_id,)
            ).fetchone()
            if row is None:
                return False
            if row[0] is not None:
                raise ValueError("Вложение требует отдельной процедуры удаления")
            result = conn.execute(
                "DELETE FROM requests WHERE id = ? AND file_id IS NULL",
                (request_id,),
            )
            return result.rowcount == 1
