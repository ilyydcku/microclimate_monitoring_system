"""Тесты практической № 7 и индивидуального варианта 17."""

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from app.auth import AuthService


GOOD = "Длинная парольная фраза 2026!"
NEW = "Другая парольная фраза 2027!"


class TestAuthV07(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.clock = [1000.0]
        # 1000 итераций допустимы только для ускорения изолированных тестов.
        self.auth = AuthService(
            Path(temp.name) / "users.sqlite3",
            clock=lambda: self.clock[0],
            rounds=1000,
        )
        self.auth.initialize()
        self.uid, self.code = self.auth.register("student_1", GOOD)

    def test_01_login(self):
        """Правильный пароль разрешает вход."""
        token = self.auth.login("student_1", GOOD)
        self.assertEqual(self.auth.resolve(token), self.uid)

    def test_02_wrong_password(self):
        """Неверный пароль отклоняется."""
        self.assertIsNone(self.auth.login("student_1", "wrong"))

    def test_03_duplicate(self):
        """Повторный логин нарушает UNIQUE."""
        with self.assertRaises(sqlite3.IntegrityError):
            self.auth.register("student_1", GOOD)

    def test_04_different_salts(self):
        """Одинаковые пароли у разных пользователей имеют разные соли."""
        self.auth.register("student_2", GOOD)
        with closing(self.auth._connect()) as conn:
            rows = conn.execute(
                "SELECT salt, password_hash FROM users ORDER BY id"
            ).fetchall()
        self.assertNotEqual(rows[0]["salt"], rows[1]["salt"])
        self.assertNotEqual(rows[0]["password_hash"], rows[1]["password_hash"])

    def test_05_no_plaintext(self):
        """Открытый пароль не записывается в таблицу."""
        with closing(self.auth._connect()) as conn:
            row = conn.execute(
                "SELECT password_hash, rounds FROM users WHERE id=?", (self.uid,)
            ).fetchone()
        self.assertNotIn(GOOD.encode(), row["password_hash"])
        self.assertEqual(row["rounds"], 1000)

    def test_06_short_rejected(self):
        """Пароль короче 15 символов запрещён при регистрации."""
        with self.assertRaises(ValueError):
            self.auth.register("student_2", "Short123")

    def test_07_spaces_are_significant(self):
        """Лишний пробел не удаляется из пароля."""
        self.assertIsNone(self.auth.login("student_1", " " + GOOD))

    def test_08_unknown_user(self):
        """Неизвестный пользователь получает отказ."""
        self.assertIsNone(self.auth.login("absent_11", GOOD))

    def test_09_lockout(self):
        """После пяти ошибок даже правильный пароль временно отвергается."""
        for _ in range(5):
            self.assertIsNone(self.auth.login("student_1", "wrong"))
        self.assertIsNone(self.auth.login("student_1", GOOD))

    def test_10_lockout_expires(self):
        """После 61 секунды вход снова возможен."""
        for _ in range(5):
            self.auth.login("student_1", "wrong")
        self.clock[0] += 61
        self.assertIsNotNone(self.auth.login("student_1", GOOD))

    def test_11_logout(self):
        """Выход отзывает сеанс на сервере."""
        token = self.auth.login("student_1", GOOD)
        self.auth.logout(token)
        self.assertIsNone(self.auth.resolve(token))

    def test_12_idle_timeout(self):
        """Бездействие дольше 15 минут завершает сеанс."""
        token = self.auth.login("student_1", GOOD)
        self.clock[0] += 901
        self.assertIsNone(self.auth.resolve(token))

    def test_13_absolute_timeout(self):
        """Абсолютный срок действует независимо от активности."""
        token = self.auth.login("student_1", GOOD)
        for _ in range(4):
            self.clock[0] += 800
            self.assertEqual(self.auth.resolve(token), self.uid)
        self.clock[0] += 400
        self.assertIsNone(self.auth.resolve(token))

    def test_14_reset_revokes(self):
        """Восстановление отзывает сеансы, старый пароль и резервный код."""
        token = self.auth.login("student_1", GOOD)
        next_code = self.auth.reset_password("student_1", self.code, NEW)
        self.assertIsNotNone(next_code)
        self.assertNotEqual(next_code, self.code)
        self.assertIsNone(self.auth.resolve(token))
        self.assertIsNone(self.auth.reset_password("student_1", self.code, GOOD))
        self.assertIsNone(self.auth.login("student_1", GOOD))
        self.assertIsNotNone(self.auth.login("student_1", NEW))

    def test_15_invalid_recovery(self):
        """Неверный резервный код не меняет пароль."""
        self.assertIsNone(
            self.auth.reset_password("student_1", "not-a-valid-code", NEW)
        )
        self.assertIsNotNone(self.auth.login("student_1", GOOD))

    # Индивидуальный вариант №17: Brute Force и Password Spraying.
    def test_16_variant17_brute_force_locks_one_account(self):
        """Brute Force: пять паролей для одного логина приводят к блокировке."""
        for guess in ("wrong1", "wrong2", "wrong3", "wrong4", "wrong5"):
            self.assertIsNone(self.auth.login("student_1", guess))
        self.assertIsNone(self.auth.login("student_1", GOOD))
        with closing(self.auth._connect()) as conn:
            blocked = conn.execute(
                "SELECT blocked_until FROM users WHERE id=?", (self.uid,)
            ).fetchone()[0]
        self.assertEqual(blocked, self.clock[0] + 60)

    def test_17_variant17_password_spraying_avoids_per_account_lock(self):
        """Spraying: один пароль по многим логинам не достигает порога на аккаунт."""
        users = []
        for i in range(6):
            uid, _ = self.auth.register(f"spray_{i}", GOOD)
            users.append((uid, f"spray_{i}"))
        for _, username in users:
            self.assertIsNone(self.auth.login(username, "CommonGuess2026!"))
        with closing(self.auth._connect()) as conn:
            state = {
                uid: conn.execute(
                    "SELECT failures, blocked_until FROM users WHERE id=?", (uid,)
                ).fetchone()
                for uid, _ in users
            }
        for uid, username in users:
            row = state[uid]
            self.assertEqual((row["failures"], row["blocked_until"]), (1, 0))
            self.assertIsNotNone(self.auth.login(username, GOOD))

    def test_18_variant17_repeated_spraying_blocks_after_five_rounds(self):
        """Пятый круг Password Spraying всё же блокирует каждую учётную запись."""
        usernames = ["spray_1", "spray_2", "spray_3"]
        for username in usernames:
            self.auth.register(username, GOOD)
        for _ in range(5):
            for username in usernames:
                self.assertIsNone(self.auth.login(username, "CommonGuess2026!"))
        for username in usernames:
            self.assertIsNone(self.auth.login(username, GOOD))
        self.clock[0] += 61
        for username in usernames:
            self.assertIsNotNone(self.auth.login(username, GOOD))

    def test_19_default_pbkdf2_rounds_in_full_auth_flow(self):
        """Обычная конфигурация использует 600000 при регистрации/входе/сбросе."""
        with tempfile.TemporaryDirectory() as temp:
            real = AuthService(Path(temp) / "users.sqlite3")
            real.initialize()
            uid, code = real.register("user_real", GOOD)
            with closing(real._connect()) as conn:
                self.assertEqual(
                    conn.execute("SELECT rounds FROM users WHERE id=?", (uid,))
                    .fetchone()[0],
                    600_000,
                )
            token = real.login("user_real", GOOD)
            self.assertEqual(real.resolve(token), uid)
            self.assertIsNotNone(real.reset_password("user_real", code, NEW))
            self.assertIsNone(real.resolve(token))
            self.assertIsNotNone(real.login("user_real", NEW))

    def test_20_only_token_hashes_are_in_sqlite(self):
        """Сеансовые токены и резервные коды не сохраняются открыто."""
        token = self.auth.login("student_1", GOOD)
        with closing(self.auth._connect()) as conn:
            stored_session = conn.execute("SELECT token_hash FROM sessions").fetchone()[0]
            stored_recovery = conn.execute(
                "SELECT recovery_hash FROM users WHERE id=?", (self.uid,)
            ).fetchone()[0]
        self.assertEqual(len(stored_session), 32)
        self.assertEqual(len(stored_recovery), 32)
        self.assertNotEqual(stored_session, token.encode())
        self.assertNotEqual(stored_recovery, self.code.encode())


if __name__ == "__main__":
    unittest.main()
