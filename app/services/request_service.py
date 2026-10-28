"""Согласованное сохранение проверенных заявок и их вложений."""

from app.repositories.requests import RequestRepository
from app.storage.files import FileStore
from app.validation import ValidatedRequest


def save_validated_request(
    request: ValidatedRequest,
    repo: RequestRepository,
    files: FileStore,
    content: bytes | None = None,
) -> tuple[int, str | None]:
    """Сохранить заявку; при ошибке SQL удалить созданное вложение."""

    if not isinstance(request, ValidatedRequest):
        raise TypeError("Нужен объект ValidatedRequest")

    if request.attachment_key is None:
        if content is not None:
            raise ValueError("Содержимое передано без категории вложения")
        return repo.add(request), None

    if content is None:
        raise ValueError("Не передано содержимое вложения")

    file_id = files.save(request.attachment_key, content)
    try:
        request_id = repo.add(request, file_id)
    except Exception:
        # SQLite и файловая система не разделяют общую транзакцию.
        files.remove(file_id)
        raise
    return request_id, file_id
