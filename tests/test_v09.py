"""Криптографические и интеграционные проверки v0.9."""
import csv
import io
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from secrets import token_bytes
from unittest.mock import patch

from app.crypto_fields import (FIELD_SCOPE, HEADER, KEY_VAR, ProtectedFieldError,
    associated_data, decrypt_field, encrypt_field, load_data_key, stored_length)
from experiment_pr9 import EXPECTED, SAMPLE, change_one_byte, observe_encryption, observe_hash_and_mac


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.key = token_bytes(32)
        self.stored = encrypt_field(SAMPLE, "1", self.key)

    def test_key_valid(self):
        with patch.dict(os.environ, {KEY_VAR: self.key.hex()}):
            self.assertEqual(load_data_key(), self.key)

    def test_key_missing(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError):
            load_data_key()

    def test_key_bad_format(self):
        for value in ("abc", "z" * 64, "0" * 63, "0" * 66, " " + "0" * 64):
            with self.subTest(value=value), patch.dict(os.environ, {KEY_VAR: value}), self.assertRaises(RuntimeError):
                load_data_key()

    def test_round_trip(self):
        self.assertEqual(decrypt_field(self.stored, "1", self.key), SAMPLE)
        self.assertTrue(self.stored.startswith(HEADER + "."))
        self.assertNotIn(SAMPLE, self.stored)

    def test_ciphertext_changed(self):
        with self.assertRaises(ProtectedFieldError):
            decrypt_field(change_one_byte(self.stored, 12), "1", self.key)

    def test_id_changed(self):
        with self.assertRaises(ProtectedFieldError):
            decrypt_field(self.stored, "2", self.key)

    def test_key_changed(self):
        with self.assertRaises(ProtectedFieldError):
            decrypt_field(self.stored, "1", bytes([self.key[0] ^ 1]) + self.key[1:])

    def test_nonce_changed(self):
        with self.assertRaises(ProtectedFieldError):
            decrypt_field(change_one_byte(self.stored, 0), "1", self.key)

    def test_tag_changed(self):
        with self.assertRaises(ProtectedFieldError):
            decrypt_field(change_one_byte(self.stored, -1), "1", self.key)

    def test_field_changed(self):
        with patch("app.crypto_fields.FIELD_SCOPE", "requests.description"), self.assertRaises(ProtectedFieldError):
            decrypt_field(self.stored, "1", self.key)
        self.assertIn(FIELD_SCOPE.encode(), associated_data("1"))

    def test_malformed(self):
        for value in (None, "", "bad.abc", HEADER + ".*", HEADER + ".AA=="):
            with self.subTest(value=value), self.assertRaises(ProtectedFieldError):
                decrypt_field(value, "1", self.key)

    def test_profile_p1(self):
        for text, n, expected in (("A", 1, 50), ("Я", 2, 50), ("…", 3, 54)):
            with self.subTest(text=text):
                self.assertEqual(len(text.encode("utf-8")), n)
                self.assertEqual(len(encrypt_field(text, "1", self.key)), expected)
                self.assertEqual(stored_length(n), expected)

    def test_all_observations(self):
        stream = io.StringIO()
        writer = csv.writer(stream)
        observe_hash_and_mac(writer)
        observe_encryption(writer, self.key)
        rows = list(csv.reader(io.StringIO(stream.getvalue())))
        self.assertEqual(len(rows), 45)
        for code, expected in EXPECTED.items():
            observed = [row for row in rows if row[0] == code]
            self.assertEqual(len(observed), 3 if code.startswith("A") else 5)
            self.assertTrue(all(row[2] == expected for row in observed))
        controls = [row for row in rows if row[0] == "B0"]
        self.assertEqual(len({row[3] for row in controls}), 5)
        self.assertTrue(all(int(row[5]) == stored_length(int(row[4])) for row in controls))


class ProtectedRequestTests(unittest.TestCase):
    def setUp(self):
        from app.auth import AuthService
        from app.authorization import initialize_authorization
        from app.crypto_service import ProtectedRequestService, initialize_crypto
        from app.repositories.requests import RequestRepository
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.database = Path(temp.name) / "test.sqlite3"
        self.auth = AuthService(self.database, rounds=1000)
        self.auth.initialize()
        RequestRepository(self.database).initialize()
        self.db = sqlite3.connect(self.database, isolation_level=None)
        self.addCleanup(self.db.close)
        initialize_authorization(self.db)
        initialize_crypto(self.db)
        env = patch.dict(os.environ, {KEY_VAR: token_bytes(32).hex()})
        env.start()
        self.addCleanup(env.stop)
        self.service = ProtectedRequestService(self.db, self.auth.resolve)
        self.tokens = {}
        self.users = {}
        self.password = "Длинная учебная парольная фраза 2026!"
        for name, role in (("owner", "user"), ("other", "user"), ("operator", "operator"), ("admin", "admin"), ("specialist", "specialist")):
            uid, _ = self.auth.register("pr9_" + name, self.password)
            self.db.execute("UPDATE users SET role=?, department_id=10 WHERE id=?", (role, uid))
            self.users[name] = uid
            self.tokens[name] = self.auth.login("pr9_" + name, self.password)
        self.rid = self.service.create_protected_request(self.tokens["owner"], "Проверка датчика", SAMPLE)

    def test_storage_and_owner(self):
        row = self.db.execute("SELECT owner_id, private_note FROM requests WHERE id=?", (self.rid,)).fetchone()
        self.assertEqual(row[0], self.users["owner"])
        self.assertNotIn(SAMPLE, row[1])
        self.assertTrue(row[1].startswith(HEADER + "."))
        self.assertEqual(self.service.read_private_note(self.tokens["owner"], self.rid), SAMPLE)

    def test_foreign_and_other_roles_denied_before_decryption(self):
        from app.authorization import AccessDenied
        with patch("app.crypto_service.decrypt_field") as decrypt:
            for user in ("other", "admin", "specialist"):
                with self.subTest(user=user), self.assertRaises(AccessDenied):
                    self.service.read_private_note(self.tokens[user], self.rid)
            decrypt.assert_not_called()

    def test_operator_reads(self):
        self.assertEqual(self.service.read_private_note(self.tokens["operator"], self.rid), SAMPLE)

    def test_reopen_database(self):
        from app.auth import AuthService
        from app.crypto_service import ProtectedRequestService
        auth2 = AuthService(self.database, rounds=1000)
        with closing(sqlite3.connect(self.database, isolation_level=None)) as db:
            service2 = ProtectedRequestService(db, auth2.resolve)
            token = auth2.login("pr9_owner", self.password)
            self.assertEqual(service2.read_private_note(token, self.rid), SAMPLE)

    def test_tampered_storage(self):
        row = self.db.execute("SELECT private_note FROM requests WHERE id=?", (self.rid,)).fetchone()
        self.db.execute("UPDATE requests SET private_note=? WHERE id=?", (change_one_byte(row[0], -1), self.rid))
        with self.assertRaises(ProtectedFieldError):
            self.service.read_private_note(self.tokens["owner"], self.rid)

    def test_transplant(self):
        rid2 = self.service.create_protected_request(self.tokens["owner"], "Вторая заявка", "Другая заметка")
        stored = self.db.execute("SELECT private_note FROM requests WHERE id=?", (self.rid,)).fetchone()[0]
        self.db.execute("UPDATE requests SET private_note=? WHERE id=?", (stored, rid2))
        with self.assertRaises(ProtectedFieldError):
            self.service.read_private_note(self.tokens["owner"], rid2)

    def test_create_denied_without_changes(self):
        from app.authorization import AccessDenied
        count = self.db.execute("SELECT count(*) FROM requests").fetchone()[0]
        for user in ("operator", "admin", "specialist"):
            with self.subTest(user=user), self.assertRaises(AccessDenied):
                self.service.create_protected_request(self.tokens[user], "Проверка датчика", SAMPLE)
        self.assertEqual(self.db.execute("SELECT count(*) FROM requests").fetchone()[0], count)

    def test_validation_before_insert(self):
        count = self.db.execute("SELECT count(*) FROM requests").fetchone()[0]
        for note in ("", "   ", "Я" * 1001, "a\x00b", 12):
            with self.subTest(note=type(note)), self.assertRaises(ValueError):
                self.service.create_protected_request(self.tokens["owner"], "Проверка датчика", note)
        self.assertEqual(self.db.execute("SELECT count(*) FROM requests").fetchone()[0], count)

    def test_encryption_failure_rollback(self):
        count = self.db.execute("SELECT count(*) FROM requests").fetchone()[0]
        with patch("app.crypto_service.encrypt_field", side_effect=ValueError), self.assertRaises(ValueError):
            self.service.create_protected_request(self.tokens["owner"], "Проверка датчика", SAMPLE)
        self.assertEqual(self.db.execute("SELECT count(*) FROM requests").fetchone()[0], count)

    def test_repeat_migration_and_legacy_data(self):
        from app.crypto_service import initialize_crypto
        legacy = self.service.create_request(self.tokens["owner"], "Старая заявка")
        initialize_crypto(self.db)
        self.assertIsNone(self.service.read_private_note(self.tokens["owner"], legacy))
        self.assertEqual(self.service.read_private_note(self.tokens["owner"], self.rid), SAMPLE)

    def test_revoked_session(self):
        from app.authorization import AccessDenied
        self.auth.logout(self.tokens["owner"])
        with self.assertRaises(AccessDenied):
            self.service.read_private_note(self.tokens["owner"], self.rid)

    def test_role_change(self):
        from app.authorization import AccessDenied
        self.service.assign_role(self.tokens["admin"], self.users["operator"], "user")
        with self.assertRaises(AccessDenied):
            self.service.read_private_note(self.tokens["operator"], self.rid)
