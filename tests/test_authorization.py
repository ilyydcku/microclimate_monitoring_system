"""Базовые, индивидуальные и интеграционные проверки версии v0.8."""

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from app.auth import AuthService
from app.authorization import (
    AccessDenied,
    AccessService,
    PERMISSIONS,
    allowed,
    initialize_authorization,
)
from app.repositories.requests import RequestRepository
from app.storage.files import FileStore
from app.validation import ValidationError, load_request


PASSWORD = "Длинная парольная фраза для проверки 2026!"
DESCRIPTION = "Учебная заявка для проверки прав доступа к данным."


class AuthorizationTests(unittest.TestCase):
    """20 базовых проверок методички и индивидуальные проверки варианта 17."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        database = Path(temp.name) / "application.sqlite3"
        auth = AuthService(database, rounds=1000)
        auth.initialize()
        RequestRepository(database).initialize()
        self.db = sqlite3.connect(database, isolation_level=None)
        self.addCleanup(self.db.close)
        initialize_authorization(self.db)

        # Реальная схема v0.7; только таблица соответствия сеансов тестовая.
        users = [
            ("user_one", "user", 1, 10),
            ("user_two", "user", 1, 20),
            ("operator_one", "operator", 1, 10),
            ("admin_one", "admin", 1, None),
            ("inactive_one", "user", 0, 10),
            ("unknown_one", "unknown", 1, 10),
            ("admin_two", "admin", 1, None),
            ("specialist_one", "specialist", 1, 10),
            ("specialist_null", "specialist", 1, None),
        ]
        self.sessions = {}
        for index, (login, role, active, department) in enumerate(users, 1):
            uid, _ = auth.register(login, PASSWORD)
            self.assertEqual(uid, index)
            self.db.execute(
                "UPDATE users SET role=?, active=?, department_id=? WHERE id=?",
                (role, active, department, uid),
            )
            self.sessions[f"s{index}"] = uid
        self.add_request(101, owner=1, department=10)
        self.add_request(102, owner=2, department=20)
        self.service = AccessService(self.db, self.sessions.get)

    def add_request(self, rid, *, owner, department, status="new", priority=3):
        self.db.execute(
            """
            INSERT INTO requests (
                id, title, description, category, priority,
                owner_id, department_id, status
            ) VALUES (?, ?, ?, 'other', ?, ?, ?, ?)
            """,
            (rid, f"Учебная заявка номер {rid}", DESCRIPTION,
             priority, owner, department, status),
        )

    def denied(self, operation, error=AccessDenied):
        before = tuple(self.db.iterdump())
        with self.assertRaises(error):
            operation()
        self.assertEqual(before, tuple(self.db.iterdump()))

    # 20 базовых проверок (№01–20) по порядку из методички.
    def test_01_owner_reads(self):
        self.assertEqual(self.service.read_request("s1", 101)["owner_id"], 1)

    def test_02_foreign_object_denied(self):
        self.denied(lambda: self.service.read_request("s1", 102))

    def test_03_operator_reads(self):
        self.assertEqual(self.service.read_request("s3", 102)["id"], 102)

    def test_04_operator_closes(self):
        self.service.close_request("s3", 101)
        self.assertEqual(self.service.read_request("s3", 101)["status"], "closed")

    def test_05_user_cannot_close(self):
        self.denied(lambda: self.service.close_request("s1", 101))

    def test_06_owner_set_by_server(self):
        rid = self.service.create_request("s1", "Новая учебная заявка")
        self.assertEqual(self.service.read_request("s1", rid)["owner_id"], 1)

    def test_07_owner_cannot_be_supplied(self):
        self.denied(
            lambda: self.service.create_request("s1", "Новая заявка", owner_id=2),
            TypeError,
        )

    def test_08_admin_cannot_read(self):
        self.denied(lambda: self.service.read_request("s4", 101))

    def test_09_admin_assigns_operator(self):
        self.service.assign_role("s4", 2, "operator")
        self.assertEqual(self.service.read_request("s2", 101)["id"], 101)

    def test_10_user_cannot_assign(self):
        self.denied(lambda: self.service.assign_role("s1", 1, "operator"))

    def test_11_operator_cannot_assign(self):
        self.denied(lambda: self.service.assign_role("s3", 2, "operator"))

    def test_12_admin_role_not_issued(self):
        self.denied(lambda: self.service.assign_role("s4", 2, "admin"))

    def test_13_admin_accounts_not_changed(self):
        for target in (4, 7):
            with self.subTest(target=target):
                self.denied(lambda: self.service.assign_role("s4", target, "user"))

    def test_14_permissions_refreshed(self):
        self.service.read_request("s3", 101)
        self.service.assign_role("s4", 3, "user")
        self.denied(lambda: self.service.close_request("s3", 101))

    def test_15_invalid_and_revoked_session(self):
        self.denied(lambda: self.service.read_request("bad", 101))
        self.sessions.pop("s1")
        self.denied(lambda: self.service.read_request("s1", 101))

    def test_16_inactive_account(self):
        self.denied(lambda: self.service.create_request("s5", "Новая заявка"))

    def test_17_unknown_role(self):
        self.denied(lambda: self.service.read_request("s6", 101))

    def test_18_unknown_permission(self):
        self.assertFalse(allowed("admin", "request.export"))
        self.assertFalse(allowed("mystery", "request.read"))

    def test_19_absent_object(self):
        self.denied(lambda: self.service.read_request("s1", 999))

    def test_20_closed_state_preserved(self):
        self.service.close_request("s3", 101)
        self.denied(lambda: self.service.close_request("s3", 101), ValueError)

    # Индивидуальный вариант 17: specialist, изменение приоритета, область Б.
    def test_21_specialist_changes_priority_in_own_department(self):
        self.service.change_priority("s8", 101, 5)
        row = self.service.read_request("s3", 101)
        self.assertEqual(row["priority"], 5)
        self.assertEqual(row["status"], "new")

    def test_22_specialist_cannot_change_foreign_department(self):
        self.denied(lambda: self.service.change_priority("s8", 102, 5))

    def test_23_missing_request_department_denied(self):
        self.add_request(103, owner=1, department=None)
        self.denied(lambda: self.service.change_priority("s8", 103, 5))

    def test_24_missing_specialist_department_denied(self):
        self.denied(lambda: self.service.change_priority("s9", 101, 5))

    def test_25_revoked_specialist_role_denied_with_same_session(self):
        self.service.change_priority("s8", 101, 4)
        self.service.assign_role("s4", 8, "user")
        self.denied(lambda: self.service.change_priority("s8", 101, 5))

    def test_26_closed_request_priority_unchanged(self):
        self.add_request(103, owner=1, department=10, status="closed")
        self.denied(lambda: self.service.change_priority("s8", 103, 5))

    def test_27_invalid_priority_rejected_without_changes(self):
        for priority in (True, 0, 6, "5", None):
            with self.subTest(priority=priority):
                self.denied(
                    lambda: self.service.change_priority("s8", 101, priority),
                    ValueError,
                )

    def test_28_only_specialist_has_new_permission(self):
        for token in ("s1", "s3", "s4"):
            with self.subTest(token=token):
                self.denied(lambda: self.service.change_priority(token, 101, 5))

    def test_29_specialist_cannot_read_or_close(self):
        self.denied(lambda: self.service.read_request("s8", 101))
        self.denied(lambda: self.service.close_request("s8", 101))

    def test_30_role_assignment_and_self_promotion_prohibited(self):
        self.service.assign_role("s4", 2, "specialist")
        self.denied(lambda: self.service.assign_role("s2", 2, "admin"))
        self.denied(lambda: self.service.assign_role("s4", 4, "specialist"))

    def test_31_client_cannot_supply_department(self):
        self.denied(
            lambda: self.service.change_priority("s8", 102, 5, department_id=20),
            TypeError,
        )

    def test_32_role_permissions_are_not_inherited(self):
        self.assertEqual(PERMISSIONS["specialist"], {"request.change_priority"})
        self.assertFalse(allowed("specialist", "request.close"))
        self.assertFalse(allowed("admin", "request.read"))

class AuthorizationIntegrationTests(unittest.TestCase):
    """Реальные сеансы AuthService с общей БД и защищенным сервисом."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.database = Path(temp.name) / "application.sqlite3"
        self.clock = [1000.0]
        self.auth = AuthService(
            self.database, rounds=1000, clock=lambda: self.clock[0]
        )
        self.auth.initialize()
        RequestRepository(self.database).initialize()
        self.db = sqlite3.connect(self.database, isolation_level=None)
        self.addCleanup(self.db.close)
        initialize_authorization(self.db)
        initialize_authorization(self.db)  # миграция должна быть повторяемой

        self.users = {}
        self.tokens = {}
        for name, department, role in (
            ("alice_one", 10, "user"),
            ("bob_two", 20, "user"),
            ("admin_one", None, "admin"),
            ("specialist_one", 10, "specialist"),
        ):
            uid, _ = self.auth.register(name, PASSWORD)
            self.users[name] = uid
            # Доверенная подготовка стенда, не внешняя операция назначения.
            self.db.execute(
                "UPDATE users SET department_id=?, role=? WHERE id=?",
                (department, role, uid),
            )
            self.tokens[name] = self.auth.login(name, PASSWORD)
        self.service = AccessService(self.db, self.auth.resolve)

    def test_33_actual_session_owner_and_foreign_request(self):
        alice = self.tokens["alice_one"]
        bob = self.tokens["bob_two"]
        rid = self.service.create_request(alice, "Заявка пользователя Alice")
        self.assertEqual(self.service.read_request(alice, rid)["owner_id"],
                         self.users["alice_one"])
        with self.assertRaises(AccessDenied):
            self.service.read_request(bob, rid)

    def test_34_real_role_refresh_with_existing_session(self):
        alice = self.tokens["alice_one"]
        admin = self.tokens["admin_one"]
        rid = self.service.create_request(alice, "Заявка для закрытия")
        self.service.assign_role(admin, self.users["alice_one"], "operator")
        self.service.close_request(alice, rid)
        self.service.assign_role(admin, self.users["alice_one"], "user")
        with self.assertRaises(AccessDenied):
            self.service.close_request(alice, rid)

    def test_35_real_session_specialist_and_role_revocation(self):
        alice = self.tokens["alice_one"]
        specialist = self.tokens["specialist_one"]
        admin = self.tokens["admin_one"]
        rid = self.service.create_request(alice, "Изменение приоритета заявки")
        self.service.change_priority(specialist, rid, 5)
        self.service.assign_role(admin, self.users["specialist_one"], "user")
        with self.assertRaises(AccessDenied):
            self.service.change_priority(specialist, rid, 4)
        self.assertEqual(self.service.read_request(alice, rid)["priority"], 5)

    def test_36_revoked_session_and_expired_session(self):
        alice = self.tokens["alice_one"]
        self.auth.logout(alice)
        with self.assertRaises(AccessDenied):
            self.service.create_request(alice, "Заявка после выхода")
        bob = self.tokens["bob_two"]
        self.clock[0] += 901
        with self.assertRaises(AccessDenied):
            self.service.create_request(bob, "Заявка после истечения")

    def test_37_inactive_account_denied_with_existing_session(self):
        token = self.tokens["alice_one"]
        self.db.execute("UPDATE users SET active=0 WHERE id=?",
                        (self.users["alice_one"],))
        with self.assertRaises(AccessDenied):
            self.service.create_request(token, "Заявка отключенного пользователя")

    def test_38_v05_rejects_client_supplied_privileged_fields(self):
        payload = {
            "title": "Заявка с лишним полем",
            "description": DESCRIPTION,
            "category": "other",
            "priority": 3,
            "role": "admin",
            "owner_id": self.users["bob_two"],
            "department_id": 10,
        }
        with self.assertRaises(ValidationError):
            load_request(json.dumps(payload).encode("utf-8"))

    def test_39_migration_preserves_v07_password_and_session_data(self):
        uid = self.users["alice_one"]
        before = self.db.execute(
            "SELECT salt, password_hash, recovery_hash FROM users WHERE id=?", (uid,)
        ).fetchone()
        initialize_authorization(self.db)
        after = self.db.execute(
            "SELECT salt, password_hash, recovery_hash FROM users WHERE id=?", (uid,)
        ).fetchone()
        self.assertEqual(tuple(before), tuple(after))
        self.assertEqual(self.auth.resolve(self.tokens["alice_one"]), uid)

    def test_40_unowned_legacy_request_denied_to_user(self):
        self.db.execute(
            """
            INSERT INTO requests (title, description, category, priority)
            VALUES (?, ?, 'other', 3)
            """,
            ("Старая запись без владельца", DESCRIPTION),
        )
        rid = self.db.execute("SELECT MAX(id) FROM requests").fetchone()[0]
        with self.assertRaises(AccessDenied):
            self.service.read_request(self.tokens["alice_one"], rid)

    def test_41_real_json_and_attachment_are_authorized(self):
        payload = {
            "title": "Заявка с журналом устройства",
            "description": DESCRIPTION,
            "category": "network",
            "priority": 2,
            "attachment_key": "log",
        }
        validated = load_request(json.dumps(payload).encode("utf-8"))
        files = FileStore(self.database.parent / "private")
        rid, file_id = self.service.create_validated_request(
            self.tokens["alice_one"], validated,
            files=files, content="Журнал оборудования\n".encode("utf-8"),
        )
        self.assertEqual(files.read(file_id), "Журнал оборудования\n".encode("utf-8"))
        row = self.service.read_request(self.tokens["alice_one"], rid)
        self.assertEqual((row["owner_id"], row["department_id"]),
                         (self.users["alice_one"], 10))

    def test_42_admin_cannot_create_with_real_json_or_file(self):
        payload = {
            "title": "Запрещенная заявка администратора",
            "description": DESCRIPTION,
            "category": "network",
            "priority": 2,
            "attachment_key": "log",
        }
        validated = load_request(json.dumps(payload).encode("utf-8"))
        files = FileStore(self.database.parent / "private")
        with self.assertRaises(AccessDenied):
            self.service.create_validated_request(
                self.tokens["admin_one"], validated,
                files=files, content=b"INFO\n",
            )
        self.assertEqual(list(files.root.iterdir()), [])

    def test_43_file_is_removed_after_insert_failure(self):
        payload = {
            "title": "Заявка с отказом SQL операции",
            "description": DESCRIPTION,
            "category": "network",
            "priority": 2,
            "attachment_key": "log",
        }
        validated = load_request(json.dumps(payload).encode("utf-8"))
        files = FileStore(self.database.parent / "private")
        self.db.execute(
            """CREATE TRIGGER reject_v08 BEFORE INSERT ON requests
               BEGIN SELECT RAISE(ABORT, 'blocked'); END"""
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.service.create_validated_request(
                self.tokens["alice_one"], validated,
                files=files, content=b"INFO\n",
            )
        self.assertEqual(list(files.root.iterdir()), [])

    def test_44_existing_v06_request_survives_schema_migration(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "existing.sqlite3"
            legacy_auth = AuthService(path, rounds=1000)
            legacy_auth.initialize()
            repo = RequestRepository(path)
            repo.initialize()
            validated = load_request(json.dumps({
                "title": "Старая заявка версии 0.6",
                "description": DESCRIPTION,
                "category": "network",
                "priority": 4,
            }).encode("utf-8"))
            rid = repo.add(validated)
            with closing(sqlite3.connect(path, isolation_level=None)) as db:
                initialize_authorization(db)
                row = db.execute(
                    "SELECT title, priority, owner_id, department_id, status "
                    "FROM requests WHERE id=?", (rid,)
                ).fetchone()
            self.assertEqual(row, ("Старая заявка версии 0.6", 4, None, None, "new"))

    def test_45_new_registration_gets_minimal_user_role(self):
        uid, _ = self.auth.register("later_user", PASSWORD)
        row = self.db.execute(
            "SELECT role, department_id FROM users WHERE id=?", (uid,)
        ).fetchone()
        self.assertEqual(tuple(row), ("user", None))

    def test_46_simple_request_uses_original_text_validation(self):
        token = self.tokens["alice_one"]
        with self.assertRaises(ValidationError):
            self.service.create_request(token, "Заявка\u202e со скрытым управлением")
        rid = self.service.create_request(token, "Вход e\u0301 в систему")
        self.assertIn("é", self.service.read_request(token, rid)["title"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
