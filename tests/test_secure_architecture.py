"""Проверки прототипов защищенной архитектуры v0.4."""

import json

import pytest

from app.audit.audit_logger import AuditLogger
from app.security.access_control import Permission, Role, has_permission
from app.security.validation import validate_measurement_input
from app.services.monitoring_service import MonitoringRecord, change_record_state


def _record() -> MonitoringRecord:
    return MonitoringRecord(
        record_id="M-202",
        temperature=21.0,
        humidity=43.0,
        status="Получено",
        allowed_engineer_ids=frozenset({"engineer_test"}),
    )


def test_valid_measurement_data_are_accepted() -> None:
    measurement = validate_measurement_input(
        source_id="SENSOR-01",
        temperature=23.0,
        humidity=48.0,
        measured_at="2026-10-07T20:00:00Z",
    )

    assert measurement.source_id == "SENSOR-01"
    assert measurement.temperature == 23.0
    assert measurement.humidity == 48.0


def test_invalid_measurement_data_are_rejected() -> None:
    with pytest.raises(ValueError, match="source_id"):
        validate_measurement_input(
            source_id="   ",
            temperature=23.0,
            humidity=48.0,
            measured_at="2026-10-07T20:00:00Z",
        )


def test_operator_has_insufficient_privileges_for_state_change(tmp_path) -> None:
    audit = AuditLogger(tmp_path / "security.log")
    record = _record()

    with pytest.raises(PermissionError):
        change_record_state(
            actor_id="operator_test",
            role=Role.OPERATOR,
            record=record,
            new_status="Проверено",
            audit_logger=audit,
        )

    assert record.status == "Получено"
    assert record.temperature == 21.0
    assert record.humidity == 43.0


def test_denied_state_change_is_written_to_audit_log(tmp_path) -> None:
    audit = AuditLogger(tmp_path / "security.log")

    with pytest.raises(PermissionError):
        change_record_state(
            actor_id="operator_test\nforged=true",
            role=Role.OPERATOR,
            record=_record(),
            new_status="Закрыто",
            audit_logger=audit,
        )

    lines = audit.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    event = json.loads(lines[0])
    assert event["action"] == "change_record_state"
    assert event["result"] == "access_denied"
    assert event["object_id"] == "M-202"
    assert "\n" not in event["actor_id"]


def test_engineer_changes_only_status_and_audit_contains_old_new_values(tmp_path) -> None:
    audit = AuditLogger(tmp_path / "security.log")
    record = _record()

    updated = change_record_state(
        actor_id="engineer_test",
        role=Role.ENGINEER,
        record=record,
        new_status="Проверено",
        audit_logger=audit,
    )

    assert updated.status == "Проверено"
    assert updated.temperature == record.temperature
    assert updated.humidity == record.humidity
    assert record.status == "Получено"

    event = json.loads(audit.path.read_text(encoding="utf-8").splitlines()[0])
    assert event["result"] == "success"
    assert event["old_value"] == "Получено"
    assert event["new_value"] == "Проверено"


def test_engineer_without_object_access_is_denied(tmp_path) -> None:
    audit = AuditLogger(tmp_path / "security.log")
    record = MonitoringRecord(
        record_id="M-203",
        temperature=20.5,
        humidity=41.0,
        status="Получено",
        allowed_engineer_ids=frozenset({"other_engineer"}),
    )

    with pytest.raises(PermissionError):
        change_record_state(
            actor_id="engineer_test",
            role=Role.ENGINEER,
            record=record,
            new_status="Проверено",
            audit_logger=audit,
        )


def test_unknown_role_has_no_permissions() -> None:
    assert not has_permission("unknown", Permission.VIEW_CURRENT)
    assert not has_permission("unknown", Permission.CHANGE_RECORD_STATE)


def test_administrator_does_not_inherit_monitoring_permissions() -> None:
    assert has_permission(Role.ADMINISTRATOR, Permission.MANAGE_USERS_AND_ROLES)
    assert not has_permission(Role.ADMINISTRATOR, Permission.VIEW_CURRENT)
    assert not has_permission(Role.ADMINISTRATOR, Permission.CHANGE_RECORD_STATE)
