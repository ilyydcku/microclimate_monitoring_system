"""Серверная модель ролей и разрешений проекта."""

from enum import Enum


class Role(str, Enum):
    """Существующие роли системы без наследования."""

    OPERATOR = "operator"
    ENGINEER = "engineer"
    ADMINISTRATOR = "administrator"


class Permission(str, Enum):
    """Разрешения, выведенные из матрицы доступа v0.2/v0.3."""

    VIEW_CURRENT = "view_current"
    VIEW_HISTORY = "view_history"
    SEARCH_AND_FILTER = "search_and_filter"
    CREATE_REPORT = "create_report"
    CHANGE_RECORD_STATE = "change_record_state"
    VIEW_SOURCE_DISPLAY_INFO = "view_source_display_info"
    CHECK_SOURCE_DETAILS = "check_source_details"
    VIEW_SOURCE_ADMIN_INFO = "view_source_admin_info"
    MANAGE_USERS_AND_ROLES = "manage_users_and_roles"
    VIEW_AUDIT_LOG = "view_audit_log"
    CHANGE_CONFIGURATION = "change_configuration"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.OPERATOR: frozenset(
        {
            Permission.VIEW_CURRENT,
            Permission.VIEW_HISTORY,
            Permission.SEARCH_AND_FILTER,
            Permission.CREATE_REPORT,
            Permission.VIEW_SOURCE_DISPLAY_INFO,
        }
    ),
    Role.ENGINEER: frozenset(
        {
            Permission.VIEW_CURRENT,
            Permission.VIEW_HISTORY,
            Permission.SEARCH_AND_FILTER,
            Permission.CREATE_REPORT,
            Permission.CHANGE_RECORD_STATE,
            Permission.VIEW_SOURCE_DISPLAY_INFO,
            Permission.CHECK_SOURCE_DETAILS,
        }
    ),
    Role.ADMINISTRATOR: frozenset(
        {
            Permission.MANAGE_USERS_AND_ROLES,
            Permission.VIEW_AUDIT_LOG,
            Permission.CHANGE_CONFIGURATION,
            Permission.VIEW_SOURCE_ADMIN_INFO,
        }
    ),
}


def has_permission(role: Role | str, permission: Permission) -> bool:
    """Проверить разрешение; неизвестная роль получает пустой набор прав."""

    try:
        normalized_role = role if isinstance(role, Role) else Role(role)
    except (TypeError, ValueError):
        return False

    return permission in ROLE_PERMISSIONS.get(normalized_role, frozenset())
