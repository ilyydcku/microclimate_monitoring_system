"""Два отдельных запуска: запись и чтение синтетической заметки из SQLite."""
import argparse
import sqlite3
from contextlib import closing
from pathlib import Path

from app.auth import AuthService
from app.authorization import AccessDenied, initialize_authorization
from app.crypto_fields import ProtectedFieldError, load_data_key
from app.crypto_service import ProtectedRequestService, initialize_crypto
from app.repositories.requests import RequestRepository
from experiment_pr9 import SAMPLE

PASSWORD = "Длинная учебная парольная фраза 2026!"


def denied(action):
    try:
        action()
    except AccessDenied:
        return True
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("create", "read", "startup"))
    parser.add_argument("--db", type=Path)
    args = parser.parse_args()
    try:
        load_data_key()
    except RuntimeError as exc:
        print(f"Startup rejected: {exc}")
        return 2
    print("Startup: OK (AES-256 key format)")
    if args.mode == "startup":
        return 0
    if args.db is None:
        parser.error("--db is required")
    if args.mode == "create" and args.db.exists():
        parser.error("Use a new database for create")
    if args.mode == "read" and not args.db.is_file():
        parser.error("Database does not exist")
    auth = AuthService(args.db)
    auth.initialize()
    RequestRepository(args.db).initialize()
    with closing(sqlite3.connect(args.db, isolation_level=None)) as db:
        initialize_authorization(db)
        initialize_crypto(db)
        service = ProtectedRequestService(db, auth.resolve)
        if args.mode == "create":
            for login, role in (("pr9_owner", "user"), ("pr9_other", "user"),
                    ("pr9_operator", "operator"), ("pr9_admin", "admin"), ("pr9_specialist", "specialist")):
                uid, _ = auth.register(login, PASSWORD)
                db.execute("UPDATE users SET role = ?, department_id = 10 WHERE id = ?", (role, uid))
            owner = auth.login("pr9_owner", PASSWORD)
            rid = service.create_protected_request(owner, "Проверка датчика микроклимата", SAMPLE)
            row = db.execute("SELECT private_note FROM requests WHERE id = ?", (rid,)).fetchone()
            stored = row[0]
            print("Request ID:", rid)
            print("Stored field:", stored)
            print("Plaintext absent from stored field:", SAMPLE not in stored)
            assert service.read_private_note(owner, rid) == SAMPLE
            auth.logout(owner)
            return 0
        rid = db.execute("SELECT id FROM requests WHERE private_note IS NOT NULL ORDER BY id LIMIT 1").fetchone()[0]
        tokens = {role: auth.login(f"pr9_{role}", PASSWORD) for role in ("owner", "other", "operator", "admin", "specialist")}
        try:
            checks = {
                "Owner after restart": service.read_private_note(tokens["owner"], rid) == SAMPLE,
                "Foreign user denied": denied(lambda: service.read_private_note(tokens["other"], rid)),
                "Operator reads": service.read_private_note(tokens["operator"], rid) == SAMPLE,
                "Admin denied": denied(lambda: service.read_private_note(tokens["admin"], rid)),
                "Specialist denied": denied(lambda: service.read_private_note(tokens["specialist"], rid)),
            }
        except ProtectedFieldError:
            print("Read rejected: protected field unavailable")
            return 3
        finally:
            for token in tokens.values():
                auth.logout(token)
        for name, result in checks.items():
            print(f"{name}: {result}")
        return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
