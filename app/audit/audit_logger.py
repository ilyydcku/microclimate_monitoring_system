"""Структурированное журналирование событий безопасности."""

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Final


_MAX_FIELD_LENGTH: Final = 256
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _sanitize(value: object | None) -> str | None:
    """Нормализовать поле журнала и исключить управляющие символы."""

    if value is None:
        return None

    text = _CONTROL_CHARS.sub(" ", str(value)).strip()
    return text[:_MAX_FIELD_LENGTH]


class AuditLogger:
    """Минимальный файловый прототип журнала безопасности.

    Компонент принимает только поля события, необходимые текущим требованиям.
    Пароли, ключи, токены и произвольные тела запросов API не принимаются.
    """

    def __init__(self, log_path: str | Path) -> None:
        self._path = Path(log_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def log_security_event(
        self,
        *,
        actor_id: object,
        action: object,
        result: object,
        object_id: object | None = None,
        old_value: object | None = None,
        new_value: object | None = None,
    ) -> None:
        """Добавить одну нормализованную JSON-строку в журнал."""

        event = {
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "actor_id": _sanitize(actor_id),
            "action": _sanitize(action),
            "result": _sanitize(result),
            "object_id": _sanitize(object_id),
            "old_value": _sanitize(old_value),
            "new_value": _sanitize(new_value),
        }

        with self._path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True))
            stream.write("\n")
