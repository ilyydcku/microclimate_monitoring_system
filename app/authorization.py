"""Ролевая и объектная авторизация заявок, практическая работа № 8."""

import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from app.storage.files import FileStore
from app.validation import ValidatedRequest, load_request


PERMISSIONS = {
    "user": frozenset({"request.create", "request.read"}),
    "operator": frozenset({"request.read", "request.close"}),
    "admin": frozenset({"role.assign"}),
    "specialist": frozenset({"request.change_priority"}),
}


class AccessDenied(PermissionError):
    """Сеанс, роль или объект не позволяют выполнить операцию."""


def allowed(role: str, action: str) -> bool:
    """Неизвестные роли и действия запрещены по умолчанию."""
    return action in PERMISSIONS.get(role, frozenset())


def initialize_authorization(db: sqlite3.Connection) -> None:
    """Дополнить фактические схемы v0.6/v0.7 без удаления старых данных.

    Предварительно вызываются AuthService.initialize() и
    RequestRepository.initialize() для ОДНОГО SQLite-файла.
    Старые заявки без owner_id и department_id не получают фиктивных прав.
    """
    db.execute("BEGIN IMMEDIATE")
    try:
        users = {row[1] for row in db.execute("PRAGMA table_info(users)")}
        requests = {row[1] for row in db.execute("PRAGMA table_info(requests)")}
        if not {"id", "active"} <= users or not {"id", "priority"} <= requests:
            raise RuntimeError("Нужны существующие таблицы users и requests")

        if "role" not in users:
            db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        if "department_id" not in users:
            db.execute("ALTER TABLE users ADD COLUMN department_id INTEGER")
        if "owner_id" not in requests:
            db.execute(
                "ALTER TABLE requests ADD COLUMN owner_id INTEGER REFERENCES users(id)"
            )
        if "department_id" not in requests:
            db.execute("ALTER TABLE requests ADD COLUMN department_id INTEGER")
        if "status" not in requests:
            db.execute(
                "ALTER TABLE requests ADD COLUMN status TEXT NOT NULL "
                "DEFAULT 'new' CHECK(status IN ('new', 'closed'))"
            )
        db.commit()
    except Exception:
        db.rollback()
        raise


class AccessService:
    """Единственная внешняя точка операций с заявками версии v0.8.

    Соединение выделено сервису и не содержит внешней открытой транзакции.
    resolve_session обязан использовать AuthService.resolve() в интеграции.
    """

    def __init__(
        self,
        db: sqlite3.Connection,
        resolve_session: Callable[[str], int | None],
    ):
        self.db = db
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.resolve_session = resolve_session

    @contextmanager
    def _operation(
        self, token: str, action: str
    ) -> Iterator[tuple[sqlite3.Row, sqlite3.Connection]]:
        # Проверка действительного сеанса до BEGIN IMMEDIATE, поскольку
        # AuthService.resolve() использует отдельное соединение к той же БД.
        uid = self.resolve_session(token)
        if type(uid) is not int or uid <= 0:
            raise AccessDenied("Операция недоступна")

        self.db.execute("BEGIN IMMEDIATE")
        try:
            user = self.db.execute(
                "SELECT id, active, role, department_id FROM users WHERE id = ?",
                (uid,),
            ).fetchone()
            if (
                user is None
                or user["active"] != 1
                or not allowed(user["role"], action)
            ):
                raise AccessDenied("Операция недоступна")
            yield user, self.db
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    @staticmethod
    def _check_id(value: int) -> None:
        if type(value) is not int or value <= 0:
            raise ValueError("Некорректный идентификатор")

    def create_request(self, token: str, title: str) -> int:
        """Создать учебную заявку, назначив владельца только на сервере."""
        with self._operation(token, "request.create") as (user, db):
            # Используем ту же проверку заголовка, что и во входном JSON v0.5.
            request = load_request(json.dumps({
                "title": title,
                "description": "Учебная заявка создана через защищенный сервис.",
                "category": "other",
                "priority": 3,
            }).encode("utf-8"))
            cursor = db.execute(
                """
                INSERT INTO requests (
                    title, description, category, priority, reporter_ip,
                    attachment_key, file_id, owner_id, department_id, status
                ) VALUES (?, ?, ?, ?, NULL, NULL, NULL, ?, ?, 'new')
                """,
                (
                    request.title,
                    request.description,
                    request.category,
                    request.priority,
                    user["id"],
                    user["department_id"],
                ),
            )
            return int(cursor.lastrowid)

    def create_validated_request(
        self,
        token: str,
        request: ValidatedRequest,
        *,
        files: FileStore | None = None,
        content: bytes | None = None,
    ) -> tuple[int, str | None]:
        """Безопасный путь v0.5→v0.6→v0.8, включая вложения.

        Вызывающий обработчик должен получить request через load_request().
        Проверка роли и INSERT выполняются в одной транзакции SQLite.
        """
        if not isinstance(request, ValidatedRequest):
            raise TypeError("Нужен объект ValidatedRequest")
        if request.attachment_key is None and content is not None:
            raise ValueError("Содержимое передано без категории вложения")
        if request.attachment_key is not None and (files is None or content is None):
            raise ValueError("Для вложения необходимы FileStore и содержимое")

        file_id = None
        try:
            with self._operation(token, "request.create") as (user, db):
                if request.attachment_key is not None:
                    file_id = files.save(request.attachment_key, content)
                cursor = db.execute(
                    """
                    INSERT INTO requests (
                        title, description, category, priority, reporter_ip,
                        attachment_key, file_id, owner_id, department_id, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')
                    """,
                    (
                        request.title,
                        request.description,
                        request.category,
                        request.priority,
                        request.reporter_ip,
                        request.attachment_key,
                        file_id,
                        user["id"],
                        user["department_id"],
                    ),
                )
                return int(cursor.lastrowid), file_id
        except Exception:
            if file_id is not None:
                files.remove(file_id)
            raise

    def read_request(self, token: str, request_id: int) -> dict:
        """Обычному пользователю доступна только собственная заявка."""
        with self._operation(token, "request.read") as (user, db):
            self._check_id(request_id)
            row = db.execute(
                """
                SELECT id, owner_id, title, status, priority, department_id
                FROM requests WHERE id = ?
                """,
                (request_id,),
            ).fetchone()
            if row is None or (
                user["role"] == "user" and row["owner_id"] != user["id"]
            ):
                # Для чужого и отсутствующего объекта одинаковый отказ.
                raise AccessDenied("Операция недоступна")
            return dict(row)

    def close_request(self, token: str, request_id: int) -> None:
        """Только оператор закрывает новую заявку."""
        with self._operation(token, "request.close") as (_, db):
            self._check_id(request_id)
            result = db.execute(
                "UPDATE requests SET status = 'closed' WHERE id = ? AND status = 'new'",
                (request_id,),
            )
            if result.rowcount != 1:
                raise ValueError("Переход состояния недоступен")

    def assign_role(self, token: str, target_id: int, role: str) -> None:
        """Администратор назначает user/operator/specialist другим людям."""
        with self._operation(token, "role.assign") as (actor, db):
            self._check_id(target_id)
            if (
                type(role) is not str
                or role not in ("user", "operator", "specialist")
                or target_id == actor["id"]
            ):
                raise AccessDenied("Операция недоступна")
            result = db.execute(
                """
                UPDATE users SET role = ?
                WHERE id = ? AND role IN ('user', 'operator', 'specialist')
                """,
                (role, target_id),
            )
            if result.rowcount != 1:
                raise AccessDenied("Операция недоступна")

    def change_priority(self, token: str, request_id: int, priority: int) -> None:
        """Вариант 17: новая заявка только своего подразделения специалиста."""
        with self._operation(token, "request.change_priority") as (actor, db):
            self._check_id(request_id)
            if type(priority) is not int or not 1 <= priority <= 5:
                raise ValueError("Приоритет должен быть целым числом от 1 до 5")
            department = actor["department_id"]
            if type(department) is not int or department <= 0:
                raise AccessDenied("Операция недоступна")
            result = db.execute(
                """
                UPDATE requests SET priority = ?
                WHERE id = ? AND status = 'new' AND department_id = ?
                """,
                (priority, request_id, department),
            )
            if result.rowcount != 1:
                raise AccessDenied("Операция недоступна")
