"""Проверки практической работы № 6 и индивидуального варианта 17."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.repositories.requests import RequestRepository
from app.security.safe_command import safe_argument
from app.services.request_service import save_validated_request
from app.storage.files import FileStore, FileValidationError, MAX_BYTES
from app.validation import load_request


def request(title="Ошибка сетевого сервиса", kind=None):
    """Создать проверенную JSON-заявку через неизменённую валидацию v0.5."""

    data = {
        "title": title,
        "description": "На сервере обнаружены неполадки, требуется диагностика.",
        "category": "network",
        "priority": 3,
        "reporter_ip": "192.0.2.10",
    }
    if kind is not None:
        data["attachment_key"] = kind
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return load_request(raw)


class TestV06(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.repo = RequestRepository(root / "data" / "requests.sqlite3")
        self.repo.initialize()
        self.files = FileStore(root / "private")

    # 15 основных сценариев из раздела 10 методички.
    def test_01_add_read(self):
        rid = self.repo.add(request())
        self.assertEqual(self.repo.get(rid)["category"], "network")

    def test_02_change(self):
        rid = self.repo.add(request())
        self.assertTrue(self.repo.set_priority(rid, 5))
        self.assertEqual(self.repo.get(rid)["priority"], 5)

    def test_03_delete(self):
        rid = self.repo.add(request())
        self.assertTrue(self.repo.delete_unattached(rid))
        self.assertIsNone(self.repo.get(rid))

    def test_04_sql_as_data(self):
        value = "' OR 1=1 --"
        self.repo.add(request(value))
        self.repo.add(request())
        with self.repo.connect() as conn:
            count = conn.execute(
                "SELECT count(*) FROM requests WHERE title = ?", (value,)
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_05_sort(self):
        with self.assertRaises(ValueError):
            self.repo.list_category("network", sort="id;DROP TABLE requests")

    def test_06_category(self):
        with self.assertRaises(ValueError):
            self.repo.list_category("network OR 1=1")

    def test_07_bool(self):
        with self.assertRaises(ValueError):
            self.repo.set_priority(1, True)

    def test_08_limit(self):
        with self.assertRaises(ValueError):
            self.repo.list_category("network", limit=101)

    def test_09_file_rw(self):
        file_id = self.files.save("log", b"INFO start\n")
        self.assertEqual(self.files.read(file_id), b"INFO start\n")

    def test_10_file_too_large(self):
        with self.assertRaises(FileValidationError):
            self.files.save("log", b"a" * (MAX_BYTES + 1))

    def test_11_file_bad_type(self):
        with self.assertRaises(FileValidationError):
            self.files.save("exe", b"hello")

    def test_12_bad_pdf(self):
        with self.assertRaises(FileValidationError):
            self.files.save("report", b"bad")

    def test_13_path(self):
        with self.assertRaises(FileValidationError):
            self.files.read("../secret")

    def test_14_bad_utf8(self):
        with self.assertRaises(FileValidationError):
            self.files.save("log", b"\xff")

    def test_15_compensation(self):
        # Проверяется реальный сервисный код компенсации, а не её ручная имитация.
        with patch.object(self.repo, "add", side_effect=sqlite3.IntegrityError):
            with self.assertRaises(sqlite3.IntegrityError):
                save_validated_request(
                    request(kind="log"), self.repo, self.files, b"LOG\n"
                )
        self.assertEqual(list(self.files.root.iterdir()), [])

    # Дополнительное индивидуальное требование безопасности № 17: UTF-8.
    def test_16_variant17_valid_cyrillic_utf8(self):
        content = "ИНФО: датчик работает\r\nПараметры: 22 °C\t45 %\n".encode("utf-8")
        file_id = self.files.save("log", content)
        self.assertEqual(self.files.read(file_id), content)

    def test_17_variant17_truncated_utf8(self):
        with self.assertRaises(FileValidationError):
            self.files.save("log", b"INFO \xd0")

    def test_18_variant17_encoded_surrogate(self):
        with self.assertRaises(FileValidationError):
            self.files.save("log", b"INFO \xed\xa0\x80")

    def test_19_variant17_utf8_bom(self):
        with self.assertRaises(FileValidationError):
            self.files.save("log", b"\xef\xbb\xbfINFO start\n")

    def test_20_variant17_direction_control(self):
        with self.assertRaises(FileValidationError):
            self.files.save("log", "INFO \u202eскрытый текст\n".encode("utf-8"))

    # Дополнительные проверки интеграции, границ и предотвращения инъекций.
    def test_21_no_attachment_integration(self):
        rid, file_id = save_validated_request(request(), self.repo, self.files)
        self.assertIsNone(file_id)
        self.assertIsNone(self.repo.get(rid)["file_id"])
        self.assertEqual(list(self.files.root.iterdir()), [])

    def test_22_content_without_attachment_rejected(self):
        with self.assertRaises(ValueError):
            save_validated_request(request(), self.repo, self.files, b"INFO\n")
        self.assertEqual(list(self.files.root.iterdir()), [])

    def test_23_attachment_without_content_rejected(self):
        with self.assertRaises(ValueError):
            save_validated_request(request(kind="log"), self.repo, self.files)

    def test_24_delete_attached_request_rejected(self):
        file_id = self.files.save("log", b"LOG\n")
        rid = self.repo.add(request(kind="log"), file_id)
        with self.assertRaises(ValueError):
            self.repo.delete_unattached(rid)
        self.assertIsNotNone(self.repo.get(rid))
        self.assertEqual(self.files.read(file_id), b"LOG\n")

    def test_25_invalid_file_id_not_inserted(self):
        with self.assertRaises(ValueError):
            self.repo.add(request(kind="log"), "../other-file")
        self.assertEqual(self.repo.list_category("network"), [])

    def test_26_allowlisted_category_sort(self):
        first = self.repo.add(request("Первая проблема"))
        second = self.repo.add(request("Вторая проблема"))
        self.repo.set_priority(first, 5)
        rows = self.repo.list_category("network", sort="priority", limit=1)
        self.assertEqual([row["id"] for row in rows], [first])
        self.assertNotEqual(first, second)

    def test_27_valid_pdf_and_png_at_storage_layer(self):
        pdf_id = self.files.save("report", b"%PDF-1.7\nTEST")
        png_id = self.files.save("screenshot", b"\x89PNG\r\n\x1a\nTEST")
        self.assertNotEqual(pdf_id, png_id)

    def test_28_read_rejects_tampered_oversized_file(self):
        file_id = self.files.save("log", b"INFO\n")
        self.files._path(file_id).write_bytes(b"a" * (MAX_BYTES + 1))
        with self.assertRaises(FileValidationError):
            self.files.read(file_id)

    def test_29_exclusive_creation_prevents_overwrite(self):
        file_id = self.files.save("log", b"FIRST\n")
        with patch("app.storage.files.secrets.token_hex", return_value=file_id):
            with self.assertRaises(RuntimeError):
                self.files.save("log", b"SECOND\n")
        self.assertEqual(self.files.read(file_id), b"FIRST\n")

    def test_30_command_metacharacters_are_data(self):
        value = "example; echo TEST"
        self.assertEqual(safe_argument(value), repr(value))

    def test_31_command_invalid_type(self):
        for value in (None, True, 12, b"value"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                safe_argument(value)

    def test_32_command_argument_too_long(self):
        with self.assertRaises(ValueError):
            safe_argument("a" * 201)


if __name__ == "__main__":
    unittest.main()
