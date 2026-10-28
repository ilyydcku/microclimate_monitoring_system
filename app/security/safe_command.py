"""Демонстрация безопасной передачи аргумента внешней программе."""

import subprocess
import sys


def safe_argument(value: str) -> str:
    """Передать строку как данные фиксированному Python-процессу."""

    if type(value) is not str or len(value) > 200:
        raise ValueError("Недопустимый аргумент")

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; print(repr(sys.argv[1]))",
            value,
        ],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    return result.stdout.strip()
