"""Точка запуска учебного защищенного приложения."""

from app.config import load_settings
from app.crypto_fields import load_data_key


def build_startup_message(app_name: str, app_env: str) -> str:
    """Сформировать сообщение без раскрытия конфиденциальных данных."""

    return f"{app_name}: приложение запущено в режиме {app_env}"


def main() -> None:
    """Запустить приложение."""

    load_data_key()
    settings = load_settings()
    message = build_startup_message(
        app_name=settings.app_name,
        app_env=settings.app_env,
    )
    print(message)


if __name__ == "__main__":
    main()
