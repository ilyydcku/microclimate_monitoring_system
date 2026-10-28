"""Интеграционная демонстрация практической работы № 6."""

import json
from pathlib import Path

from app.repositories.requests import RequestRepository
from app.security.safe_command import safe_argument
from app.services.request_service import save_validated_request
from app.storage.files import FileStore
from app.validation import load_request


def main() -> None:
    root = Path(__file__).resolve().parent
    repo = RequestRepository(root / "data" / "requests.sqlite3")
    repo.initialize()
    files = FileStore(root / "private_data" / "attachments")

    payload = {
        "title": "Ошибка сетевого сервиса",
        "description": "На сервере обнаружены неполадки, требуется диагностика.",
        "category": "network",
        "priority": 3,
        "reporter_ip": "192.0.2.10",
        "attachment_key": "log",
    }
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = load_request(raw)
    content = b"INFO Service started\n"

    request_id, file_id = save_validated_request(request, repo, files, content)
    print("ID заявки:", request_id)
    print("ID файла:", file_id)
    print("Содержимое совпадает:", files.read(file_id) == content)
    print("Специальные символы как данные:", safe_argument("example; echo TEST"))


if __name__ == "__main__":
    main()
