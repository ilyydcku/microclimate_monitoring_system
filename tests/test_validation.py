"""Позитивные и негативные проверки практической работы 5."""

import json
import unittest

from app.validation import (
    MAX_REQUEST_BYTES,
    ValidationError,
    get_attachment_path,
    load_request,
)


def valid_payload():
    return {
        "title": " Ошибка сервиса ",
        "description": "На узле обнаружены неполадки, требуется диагностика.",
        "category": " Network ",
        "priority": 3,
        "reporter_ip": " 192.0.2.10 ",
        "attachment_key": "log",
    }


def encoded(payload):
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


class RequestValidationTests(unittest.TestCase):
    def test_valid(self):
        data = load_request(encoded(valid_payload()))
        self.assertEqual(data.title, "Ошибка сервиса")
        self.assertEqual(data.category, "network")
        self.assertEqual(data.reporter_ip, "192.0.2.10")

    def test_optional_fields(self):
        payload = valid_payload()
        del payload["reporter_ip"]
        del payload["attachment_key"]
        self.assertIsNone(load_request(encoded(payload)).attachment_key)

    def test_bool_priority_rejected(self):
        payload = valid_payload()
        payload["priority"] = True
        with self.assertRaises(ValidationError):
            load_request(encoded(payload))

    def test_str_priority_rejected(self):
        payload = valid_payload()
        payload["priority"] = "3"
        with self.assertRaises(ValidationError):
            load_request(encoded(payload))

    def test_out_of_range(self):
        payload = valid_payload()
        payload["priority"] = 6
        with self.assertRaises(ValidationError):
            load_request(encoded(payload))

    # Обязательный сценарий 7 из таблицы методички.
    def test_priority_below_one_rejected(self):
        payload = valid_payload()
        payload["priority"] = 0
        with self.assertRaises(ValidationError):
            load_request(encoded(payload))

    def test_short_title(self):
        payload = valid_payload()
        payload["title"] = "А"
        with self.assertRaises(ValidationError):
            load_request(encoded(payload))

    def test_oversized_description(self):
        payload = valid_payload()
        payload["description"] = "x" * 2001
        with self.assertRaises(ValidationError):
            load_request(encoded(payload))

    def test_unknown_field(self):
        payload = valid_payload()
        payload["is_admin"] = True
        with self.assertRaises(ValidationError):
            load_request(encoded(payload))

    def test_missing_field(self):
        payload = valid_payload()
        del payload["category"]
        with self.assertRaises(ValidationError):
            load_request(encoded(payload))

    def test_wrong_category(self):
        payload = valid_payload()
        payload["category"] = "administrator"
        with self.assertRaises(ValidationError):
            load_request(encoded(payload))

    def test_invalid_ip(self):
        payload = valid_payload()
        payload["reporter_ip"] = "999.3.2.1"
        with self.assertRaises(ValidationError):
            load_request(encoded(payload))

    def test_ipv6(self):
        payload = valid_payload()
        payload["reporter_ip"] = "2001:0db8::0001"
        self.assertEqual(load_request(encoded(payload)).reporter_ip, "2001:db8::1")

    def test_traversal_key(self):
        payload = valid_payload()
        payload["attachment_key"] = "../secret"
        with self.assertRaises(ValidationError):
            load_request(encoded(payload))

    def test_duplicate_json_keys(self):
        raw = b'{"x":1,"x":2}'
        with self.assertRaises(ValidationError):
            load_request(raw)

    def test_nan(self):
        with self.assertRaises(ValidationError):
            load_request(b'{"priority":NaN}')

    def test_large_request(self):
        with self.assertRaises(ValidationError):
            load_request(b" " * (MAX_REQUEST_BYTES + 1))

    def test_bad_json(self):
        with self.assertRaises(ValidationError):
            load_request(b"{")

    def test_control_char(self):
        payload = valid_payload()
        payload["title"] = "Имя\x00 заявки"
        with self.assertRaises(ValidationError):
            load_request(encoded(payload))

    def test_html_as_data(self):
        payload = valid_payload()
        payload["description"] = (
            "<script>alert('x')</script> "
            "Текст заявки допускает разметку как текст"
        )
        self.assertIn("<script>", load_request(encoded(payload)).description)

    def test_surrogate_rejected(self):
        payload = valid_payload()
        payload["title"] = "Проблема\ud800"
        with self.assertRaises(ValidationError):
            load_request(json.dumps(payload, ensure_ascii=True).encode("utf-8"))

    def test_nfc(self):
        payload = valid_payload()
        payload["title"] = "Проблема Cafe\u0301"
        self.assertEqual(load_request(encoded(payload)).title, "Проблема Café")

    # Дополнительные проверки варианта 17 (1 позитивная, 2 негативные).
    def test_variant17_log_accepted(self):
        payload = valid_payload()
        payload["attachment_key"] = "log"
        self.assertEqual(load_request(encoded(payload)).attachment_key, "log")
        self.assertEqual(get_attachment_path("log").name, "network.log")

    def test_variant17_screenshot_rejected(self):
        payload = valid_payload()
        payload["attachment_key"] = "screenshot"
        with self.assertRaises(ValidationError):
            load_request(encoded(payload))

    def test_variant17_report_rejected(self):
        payload = valid_payload()
        payload["attachment_key"] = "report"
        with self.assertRaises(ValidationError):
            load_request(encoded(payload))
        with self.assertRaises(ValidationError):
            get_attachment_path("../secret")


if __name__ == "__main__":
    unittest.main()