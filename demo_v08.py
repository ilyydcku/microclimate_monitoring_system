"""Воспроизводимая интеграционная демонстрация RBAC v0.8, вариант 17.

Используются настоящие AuthService, SQLite, валидация и AccessService.
Все записи учебные, база находится во временном каталоге.
"""

import json
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from app.auth import AuthService
from app.authorization import AccessDenied, AccessService, initialize_authorization
from app.repositories.requests import RequestRepository
from app.validation import load_request


PASSWORD = "Длинная учебная парольная фраза 2026!"


def denied(action) -> bool:
    try:
        action()
    except AccessDenied:
        return True
    return False


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="v08_microclimate_") as temp:
        database = Path(temp) / "application.sqlite3"
        auth = AuthService(database)
        auth.initialize()
        RequestRepository(database).initialize()

        with closing(sqlite3.connect(database, isolation_level=None)) as db:
            initialize_authorization(db)
            users = {}
            tokens = {}
            for login, role, department in (
                ("sample_alice", "user", 10),
                ("sample_bob", "user", 20),
                ("sample_admin", "admin", None),
                ("sample_specialist", "specialist", 10),
            ):
                uid, _ = auth.register(login, PASSWORD)
                users[login] = uid
                # Только доверенная подготовка стенда. Клиент не передает role.
                db.execute(
                    "UPDATE users SET role=?, department_id=? WHERE id=?",
                    (role, department, uid),
                )
                tokens[login] = auth.login(login, PASSWORD)

            service = AccessService(db, auth.resolve)
            alice = tokens["sample_alice"]
            bob = tokens["sample_bob"]
            admin = tokens["sample_admin"]
            specialist = tokens["sample_specialist"]

            request = load_request(json.dumps({
                "title": "Проблема датчика микроклимата",
                "description": "В учебном контуре обнаружено отклонение показаний.",
                "category": "network",
                "priority": 2,
            }, ensure_ascii=False).encode("utf-8"))
            rid, _ = service.create_validated_request(alice, request)

            print("Версия: 0.8; вариант: 17")
            print("Проверка реального сеанса:", auth.resolve(alice) == users["sample_alice"])
            print("Создание и владелец:", service.read_request(alice, rid)["owner_id"] == users["sample_alice"])
            print("Отказ при чтении чужой заявки:", denied(lambda: service.read_request(bob, rid)))
            print("Отказ администратору на чтение:", denied(lambda: service.read_request(admin, rid)))

            service.change_priority(specialist, rid, 5)
            print("Вариант 17, свое подразделение:", service.read_request(alice, rid)["priority"] == 5)
            other = service.create_request(bob, "Заявка другого подразделения")
            print("Вариант 17, чужое подразделение:", denied(lambda: service.change_priority(specialist, other, 4)))

            service.assign_role(admin, users["sample_bob"], "operator")
            service.close_request(bob, rid)
            print("Оператор закрыл заявку:", service.read_request(alice, rid)["status"] == "closed")
            service.assign_role(admin, users["sample_bob"], "user")
            print("Отзыв роли при старом сеансе:", denied(lambda: service.close_request(bob, other)))

            service.assign_role(admin, users["sample_specialist"], "user")
            print("Отзыв specialist при старом сеансе:", denied(lambda: service.change_priority(specialist, other, 4)))
            auth.logout(alice)
            print("Отзыв реального сеанса:", denied(lambda: service.read_request(alice, rid)))


if __name__ == "__main__":
    main()
