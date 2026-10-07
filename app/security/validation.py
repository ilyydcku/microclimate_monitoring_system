"""Проверка недоверенных входных данных до передачи в бизнес-логику."""

from dataclasses import dataclass
import math
from numbers import Real


@dataclass(frozen=True)
class MeasurementInput:
    """Технически проверенные поля входящего показания.

    Физические допустимые диапазоны параметров здесь намеренно не задаются:
    они отсутствуют в исходных требованиях проекта.
    """

    source_id: str
    temperature: float
    humidity: float
    measured_at: str


def validate_required_text(
    value: object,
    *,
    field_name: str,
    max_length: int = 128,
) -> str:
    """Проверить обязательное текстовое поле без предметных предположений."""

    if not isinstance(value, str):
        raise ValueError(f"{field_name}: ожидается строка")

    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name}: значение не может быть пустым")
    if len(normalized) > max_length:
        raise ValueError(f"{field_name}: значение слишком длинное")

    return normalized


def validate_finite_number(value: object, *, field_name: str) -> float:
    """Проверить, что значение является конечным числом."""

    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{field_name}: ожидается число")

    normalized = float(value)
    if not math.isfinite(normalized):
        raise ValueError(f"{field_name}: число должно быть конечным")

    return normalized


def validate_measurement_input(
    *,
    source_id: object,
    temperature: object,
    humidity: object,
    measured_at: object,
) -> MeasurementInput:
    """Выполнить техническую валидацию входящего показания."""

    return MeasurementInput(
        source_id=validate_required_text(
            source_id,
            field_name="source_id",
            max_length=128,
        ),
        temperature=validate_finite_number(
            temperature,
            field_name="temperature",
        ),
        humidity=validate_finite_number(
            humidity,
            field_name="humidity",
        ),
        measured_at=validate_required_text(
            measured_at,
            field_name="measured_at",
            max_length=128,
        ),
    )


def validate_state_change_input(*, record_id: object, new_status: object) -> tuple[str, str]:
    """Проверить технические поля операции изменения состояния записи."""

    return (
        validate_required_text(record_id, field_name="record_id", max_length=128),
        validate_required_text(new_status, field_name="new_status", max_length=128),
    )
