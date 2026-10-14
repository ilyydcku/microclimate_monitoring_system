
"""Безопасная точка входа для обработки JSON-заявок."""

import json
import sys

from app.validation import (
    MAX_REQUEST_BYTES,
    ValidationError,
    load_request,
)


def main():
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)

    try:
        request = load_request(raw)
    except ValidationError as exc:
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "field": exc.field,
                    "message": str(exc),
                },
                ensure_ascii=False,
            )
        )
        return 2

    print(
        json.dumps(
            {
                "status": "accepted",
                "category": request.category,
                "priority": request.priority,
                "attachment": request.attachment_key is not None,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
