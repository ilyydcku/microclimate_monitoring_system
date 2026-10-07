"""Прототип сервисной операции системы мониторинга микроклимата."""

from dataclasses import dataclass, replace

from app.audit.audit_logger import AuditLogger
from app.security.access_control import Permission, Role, has_permission
from app.security.validation import validate_state_change_input


@dataclass(frozen=True)
class MonitoringRecord:
    """Минимальная модель записи для демонстрации защитных инвариантов."""

    record_id: str
    temperature: float
    humidity: float
    status: str
    allowed_engineer_ids: frozenset[str]


def change_record_state(
    *,
    actor_id: str,
    role: Role | str,
    record: MonitoringRecord,
    new_status: str,
    audit_logger: AuditLogger,
) -> MonitoringRecord:
    """Изменить только состояние доступной записи и обязательно создать аудит."""

    record_id, normalized_status = validate_state_change_input(
        record_id=record.record_id,
        new_status=new_status,
    )

    role_allowed = has_permission(role, Permission.CHANGE_RECORD_STATE)
    object_allowed = actor_id in record.allowed_engineer_ids
    if not role_allowed or not object_allowed:
        audit_logger.log_security_event(
            actor_id=actor_id,
            action="change_record_state",
            result="access_denied",
            object_id=record_id,
            old_value=record.status,
            new_value=normalized_status,
        )
        raise PermissionError("Недостаточно полномочий для изменения состояния записи")

    updated = replace(record, status=normalized_status)

    audit_logger.log_security_event(
        actor_id=actor_id,
        action="change_record_state",
        result="success",
        object_id=record_id,
        old_value=record.status,
        new_value=normalized_status,
    )

    return updated
