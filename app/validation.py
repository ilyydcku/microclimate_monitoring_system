
"""Безопасный прием JSON-заявок до передачи в бизнес-логику."""

import ipaddress
import json
import unicodedata
from dataclasses import dataclass
from pathlib import Path


MAX_REQUEST_BYTES = 8192
ALLOWED_CATEGORIES = {"network", "software", "access", "other"}
# Индивидуальный вариант 17: разрешен только тип вложения log.
ALLOWED_ATTACHMENTS = {"log"}
REQUIRED_FIELDS = {"title", "description", "category", "priority"}
OPTIONAL_FIELDS = {"reporter_ip", "attachment_key"}

# Пользователь выбирает логический ключ, а не путь к файлу.
BASE_DIR = Path(__file__).resolve().parent.parent / "attachments"
FILES = {"log": "network.log"}


class ValidationError(ValueError):
    """Ошибка проверки: имя поля и безопасное сообщение."""

    def __init__(self, field: str, message: str):
        self.field = field
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ValidatedRequest:
    """Проверенная заявка для передачи в прикладной компонент."""

    title: str
    description: str
    category: str
    priority: int
    reporter_ip: str | None
    attachment_key: str | None


def _unique_object(pairs):
    """Отклонить повторяющиеся ключи JSON."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("$", "В JSON обнаружены повторяющиеся ключи")
        result[key] = value
    return result


def _reject_constant(value):
    """Отклонить NaN, Infinity и -Infinity."""
    raise ValidationError("$", "Недопустимое числовое значение в JSON")


def _text(value, field, minimum, maximum, multiline=False):
    """Нормализовать и проверить текстовое поле."""
    if not isinstance(value, str):
        raise ValidationError(field, "Ожидается строка")

    normalized = unicodedata.normalize(
        "NFC", value.replace("\r\n", "\n").strip()
    )

    for char in normalized:
        if unicodedata.category(char) in {"Cc", "Cf", "Cs"}:
            if not (multiline and char == "\n"):
                raise ValidationError(field, "Недопустимый управляющий символ")

        if not multiline and char in {"\u2028", "\u2029"}:
            raise ValidationError(field, "Перенос строки недопустим")

    if not minimum <= len(normalized) <= maximum:
        raise ValidationError(
            field, f"Допустимая длина: {minimum}-{maximum}"
        )

    return normalized


def load_request(raw: bytes) -> ValidatedRequest:
    """Проверить JSON и вернуть объект с проверенными данными."""

    if not isinstance(raw, bytes):
        raise ValidationError("$", "Ожидается JSON в виде байтов")

    if len(raw) > MAX_REQUEST_BYTES:
        raise ValidationError("$", "Превышен допустимый размер запроса")

    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ValidationError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise ValidationError(
            "$", "Некорректный JSON или кодировка UTF-8"
        ) from exc

    if not isinstance(payload, dict):
        raise ValidationError("$", "Ожидается JSON-объект")

    if REQUIRED_FIELDS - payload.keys():
        raise ValidationError("$", "Отсутствуют обязательные поля")

    if payload.keys() - (REQUIRED_FIELDS | OPTIONAL_FIELDS):
        raise ValidationError("$", "Обнаружены неизвестные поля")

    title = _text(payload["title"], "title", 5, 100)

    description = _text(
        payload["description"],
        "description",
        20,
        2000,
        multiline=True,
    )

    category = _text(
        payload["category"], "category", 1, 30
    ).casefold()

    if category not in ALLOWED_CATEGORIES:
        raise ValidationError("category", "Неизвестная категория")

    priority = payload["priority"]

    if type(priority) is not int or not 1 <= priority <= 5:
        raise ValidationError(
            "priority",
            "Приоритет должен быть целым числом от 1 до 5",
        )

    reporter_ip = payload.get("reporter_ip")

    if reporter_ip is not None:
        reporter_ip = _text(
            reporter_ip, "reporter_ip", 2, 45
        )

        if "%" in reporter_ip:
            raise ValidationError(
                "reporter_ip", "Зона IPv6 не поддерживается"
            )

        try:
            reporter_ip = str(
                ipaddress.ip_address(reporter_ip)
            )
        except ValueError as exc:
            raise ValidationError(
                "reporter_ip", "Некорректный IP-адрес"
            ) from exc

    attachment_key = payload.get("attachment_key")

    if attachment_key is not None:
        attachment_key = _text(
            attachment_key, "attachment_key", 1, 20
        )

        if attachment_key not in ALLOWED_ATTACHMENTS:
            raise ValidationError(
                "attachment_key",
                "Неизвестный идентификатор вложения",
            )

    return ValidatedRequest(
        title=title,
        description=description,
        category=category,
        priority=priority,
        reporter_ip=reporter_ip,
        attachment_key=attachment_key,
    )


def get_attachment_path(key: str) -> Path:
    """Сопоставить логический ключ с фиксированным путем."""
    if not isinstance(key, str) or key not in FILES:
        raise ValidationError(
            "attachment_key",
            "Неизвестный идентификатор вложения",
        )

    return BASE_DIR / FILES[key]
