"""Тесты первоначальной версии приложения."""

from app.main import build_startup_message


def test_startup_message_contains_application_name() -> None:
    """Сообщение должно содержать название приложения."""

    message = build_startup_message(
        app_name="Microclimate Monitoring System",
        app_env="testing",
    )

    assert "Microclimate Monitoring System" in message


def test_startup_message_contains_environment() -> None:
    """Сообщение должно содержать режим работы."""

    message = build_startup_message(
        app_name="Microclimate Monitoring System",
        app_env="testing",
    )

    assert "testing" in message


def test_startup_message_does_not_contain_secret() -> None:
    """Секрет не должен попадать в стартовое сообщение."""

    secret = "very_secret_value_1234567890"
    message = build_startup_message(
        app_name="Microclimate Monitoring System",
        app_env="testing",
    )

    assert secret not in message
