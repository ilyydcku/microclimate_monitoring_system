"""Демонстрация практической работы № 7 (учебные данные)."""

import sqlite3
from pathlib import Path

from app.auth import AuthService


def main():
    root = Path(__file__).resolve().parent
    auth = AuthService(root / "data" / "users.sqlite3")
    auth.initialize()

    login = "student_17"
    password = "Длинная парольная фраза 2026!"  # Только учебный пароль.
    try:
        user_id, recovery_code = auth.register(login, password)
        print("Создан пользователь:", user_id)
        # Демонстрационная выдача единственный раз при регистрации.
        # В реальном приложении не логировать резервные коды.
        print("Резервный код:", recovery_code)
    except sqlite3.IntegrityError:
        print("Учётная запись уже существует")

    token = auth.login(login, password)
    if token is None:
        print("Не удалось выполнить вход")
        return
    print("Аутентификация выполнена")
    user_id = auth.resolve(token)
    print("Подтверждённый ID:", user_id)
    auth.logout(token)
    print("После выхода:", auth.resolve(token))


if __name__ == "__main__":
    main()
