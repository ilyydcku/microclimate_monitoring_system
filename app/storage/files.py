"""Ограниченное файловое хранилище с непредсказуемыми ID."""

import os
import re
import secrets
import stat
import unicodedata
from pathlib import Path


MAX_BYTES = 1_048_576
ALLOWED_KINDS = {"log", "report", "screenshot"}


class FileValidationError(ValueError):
    """Недопустимое содержимое или идентификатор вложения."""


def check_file(kind: str, data: bytes) -> None:
    """Проверить категорию, размер и основные признаки содержимого."""

    if type(kind) is not str or kind not in ALLOWED_KINDS:
        raise FileValidationError("Категория запрещена")
    if type(data) is not bytes or not 0 < len(data) <= MAX_BYTES:
        raise FileValidationError("Размер или тип недопустим")

    if kind == "log":
        try:
            decoded = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise FileValidationError("Журнал должен быть UTF-8") from exc

        # Дополнительное правило индивидуального варианта 17: без BOM и
        # скрытых/управляющих символов, кроме табуляции и переводов строк.
        if decoded.startswith("\ufeff"):
            raise FileValidationError("UTF-8 BOM в начале журнала запрещён")
        if any(
            unicodedata.category(char) in {"Cc", "Cf", "Cs"}
            and char not in {"\t", "\n", "\r"}
            for char in decoded
        ):
            raise FileValidationError("Управляющий символ в журнале запрещён")

    elif kind == "report":
        if not data.startswith(b"%PDF-"):
            raise FileValidationError("Не PDF")
    elif kind == "screenshot":
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise FileValidationError("Не PNG")


class FileStore:
    """Файловое хранилище в защищённом локальном каталоге."""

    def __init__(self, root: Path):
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("Не каталог")

    def _path(self, file_id: str) -> Path:
        if (
            type(file_id) is not str
            or re.fullmatch(r"[0-9a-f]{32}", file_id) is None
        ):
            raise FileValidationError("Неверный идентификатор")
        return self.root / f"{file_id}.bin"

    def save(self, kind: str, data: bytes) -> str:
        """Проверить и записать файл без риска перезаписи по его имени."""

        check_file(kind, data)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        for _ in range(5):
            file_id = secrets.token_hex(16)
            path = self._path(file_id)
            try:
                fd = os.open(path, flags, 0o600)
            except FileExistsError:
                continue
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
            except BaseException:
                path.unlink(missing_ok=True)
                raise
            return file_id
        raise RuntimeError("Не удалось создать имя")

    def read(self, file_id: str) -> bytes:
        """Читать только обычный файл в пределах установленного лимита."""

        path = self._path(file_id)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BYTES:
                raise FileValidationError("Недопустимый объект или размер")
            data = stream.read(MAX_BYTES + 1)
            if not 0 < len(data) <= MAX_BYTES:
                raise FileValidationError("Недопустимый размер")
            return data

    def remove(self, file_id: str) -> None:
        """Внутреннее удаление файла по проверенному ID."""

        self._path(file_id).unlink(missing_ok=True)
