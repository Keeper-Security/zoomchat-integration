# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""Utility functions for Keeper Zoom Integration."""

import os
import re
import uuid
from datetime import datetime
from typing import Any, Optional, Tuple

from .logger import logger


CHANNEL_JID_SUFFIX = "@conference.xmpp.zoom.us"


def _collapse_for_log(value: Any, default: str = "N/A") -> str:
    """Return a single-line representation for audit log fields."""
    if value is None:
        return default
    text = " ".join(str(value).split())
    return text or default


def format_approval_audit_log(
    *,
    approval_id: str,
    request_type: str,
    identifier: str,
    requester_email: str,
    approver_email: str,
    permission: str,
    duration_text: str,
    rotate_on_expire: bool = False,
    is_pam: bool = False,
) -> str:
    """Format Keeper approval audit details"""
    request_type_text = _collapse_for_log(request_type).replace("_", " ")
    action = f"Granted {request_type_text} access"

    permission_label = format_permission_name(_collapse_for_log(permission, ""))

    details = [
        f"Approval {_collapse_for_log(approval_id)}: {action}",
        f"(UID: {_collapse_for_log(identifier)})",
        f"for user {_collapse_for_log(requester_email)}",
        f"approved by {_collapse_for_log(approver_email)}",
        f"with {permission_label} permission",
        f"for {_collapse_for_log(duration_text)}",
    ]

    if is_pam and rotate_on_expire:
        details.append("auto-rotate enabled")

    return ", ".join(details)


def is_pam_record_type(record_type: str) -> bool:
    """True if the record type is a PAM record (pamUser, pamMachine, etc.)."""
    return bool(record_type) and 'pam' in record_type.lower()


def is_pam_user_record_type(record_type: str) -> bool:
    """True only for the pamUser record type (rotation flow target)."""
    return bool(record_type) and record_type.strip().lower() == 'pamuser'


def is_running_in_docker() -> bool:
    """
    Check if the application is running inside a Docker container.
    """
    if os.path.exists('/.dockerenv'):
        return True

    try:
        with open('/proc/1/cgroup', 'r') as f:
            return 'docker' in f.read()
    except Exception:
        pass

    return False


def fix_service_url_for_docker(service_url: str) -> str:
    """
    Replace localhost with the 'commander-zoom' service name in Docker
    environments so containers can reach each other.
    """
    if not service_url or not is_running_in_docker():
        return service_url

    if 'localhost' in service_url.lower() or '127.0.0.1' in service_url:
        service_url = service_url.replace('localhost', 'commander-zoom')
        service_url = service_url.replace('127.0.0.1', 'commander-zoom')

    return service_url


def is_channel_jid(jid: Optional[str]) -> bool:
    """True if the JID is a Zoom Team Chat channel (not a 1:1 chat)."""
    return bool(jid) and jid.lower().endswith(CHANNEL_JID_SUFFIX)


def generate_approval_id() -> str:
    """
    Generate a unique approval request ID.
    """
    date_part = datetime.now().strftime('%Y%m%d')
    random_part = str(uuid.uuid4())[:5]
    return f"APR-{date_part}-{random_part}"


def is_valid_uid(identifier: str) -> bool:
    """
    Check if a string is a valid Keeper UID format.
    """
    # Remove chat markdown formatting that might have been applied
    cleaned = identifier.strip('*_~`')

    # Keeper UIDs are typically 22 chars, but allow 20-24 for flexibility
    # Valid characters: letters, numbers, -, _
    uid_pattern = r'^[A-Za-z0-9_-]{20,24}$'
    return bool(re.match(uid_pattern, cleaned))


def is_record_owner_error(error_message: str) -> bool:
    """Check if error is due to user being the record owner."""
    error_lower = error_message.lower()
    return (
        "cannot grant access to record owner" in error_lower or
        "already owns this record" in error_lower
    )


def is_permission_conflict_error(error_message: str) -> bool:
    """
    Check if the error is a permission conflict that requires manual revocation.
    These errors should not close the approval card.
    """
    error_lower = error_message.lower()
    conflict_indicators = [
        "already has temporary access",
        "already has existing permissions",
        "conflicts with the selected permission level",
        "first remove the user's existing access",
        "first revoke the user's existing access"
    ]
    return any(indicator in error_lower for indicator in conflict_indicators)


def parse_command_text(text: str) -> Tuple[str, str]:
    """
    Parse slash command text into identifier and justification.

    Accepts ``"quoted description" justification``, ``'quoted' justification``
    or ``UID justification``. Zoom clients sometimes send smart quotes, which
    are normalised first.
    """
    text = (text or "").strip()
    text = text.replace('“', '"').replace('”', '"')
    text = text.replace('‘', "'").replace('’', "'")

    if not text:
        return "", ""

    identifier = ""
    justification = ""

    if text.startswith('"'):
        end_quote = text.find('"', 1)
        if end_quote != -1:
            identifier = text[1:end_quote]
            justification = text[end_quote + 1:].strip()
    elif text.startswith("'"):
        end_quote = text.find("'", 1)
        if end_quote != -1:
            identifier = text[1:end_quote]
            justification = text[end_quote + 1:].strip()
    else:
        parts = text.split(None, 1)
        identifier = parts[0] if parts else ""
        justification = parts[1] if len(parts) > 1 else ""

    # Clean markdown formatting from identifier (*, _, ~, `)
    if identifier:
        identifier = identifier.strip('*_~`')

    return identifier, justification


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """
    Format a datetime for display in Zoom.
    """
    if dt is None:
        dt = datetime.now()
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def format_local_time(dt: datetime) -> str:
    """
    Format an expiry time with its timezone. Zoom has no equivalent of Slack's
    ``<!date^…>`` per-viewer timezone token, so the server timezone is shown.
    """
    return dt.astimezone().strftime('%Y-%m-%d %H:%M %Z').strip()


def truncate_text(text: str, max_length: int = 100) -> str:
    """
    Truncate text to maximum length with ellipsis.
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def sanitize_hyperlinks(text: str) -> str:
    """
    Sanitize hyperlinks in text to prevent URL injection attacks.
    Removes colons and forward slashes that could create clickable URLs.
    """
    if not text:
        return text

    sanitized = text.replace(':', '')
    sanitized = sanitized.replace('/', '')
    return sanitized


# Maximum allowed length for user input fields
MAX_JUSTIFICATION_LENGTH = 500
MAX_IDENTIFIER_LENGTH = 200


def sanitize_command_input(text: str) -> str:
    """
    Sanitize user input to prevent command injection and URL injection.
    Removes shell special characters and URL characters.
    Note: Quotes are kept as-is for display; shell escaping is handled at command execution.
    """
    if not text:
        return text

    # Note: '/' is intentionally NOT included - it's needed for searching records with paths
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']',
                       '!', '\\', '\n', '\r', '\x00', ':']

    sanitized = text
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')

    return sanitized.strip()


def sanitize_chat_mentions(text: str) -> str:
    """
    Prevents @all / @here / @channel / @everyone spam in the approvals channel.
    """
    if not text:
        return text

    patterns = [
        r'@all\b\s*',
        r'@here\b\s*',
        r'@channel\b\s*',
        r'@everyone\b\s*',
    ]

    sanitized = text
    for pattern in patterns:
        sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)

    return sanitized.strip()


def validate_input_length(text: str, max_length: int, field_name: str = "Input") -> Tuple[bool, str]:
    """
    Validate that input text doesn't exceed maximum length.
    """
    if not text:
        return True, ""

    if len(text) > max_length:
        return False, f"{field_name} is too long. Maximum {max_length} characters allowed (you have {len(text)})."

    return True, ""


def sanitize_user_input(text: str, max_length: int = MAX_JUSTIFICATION_LENGTH) -> Tuple[str, bool, str]:
    """
    Apply all input sanitization and validation.
    """
    if not text:
        return text, True, ""

    is_valid, error_msg = validate_input_length(text, max_length)
    if not is_valid:
        return text, False, error_msg

    sanitized = sanitize_chat_mentions(text)
    sanitized = sanitize_command_input(sanitized)

    return sanitized, True, ""


def format_permission_name(permission: str) -> str:
    """
    Format permission level for display.
    """
    mappings = {
        # Classic record permissions
        'view_only': 'View Only',
        'can_edit': 'Can Edit',
        'can_share': 'Can Share',
        'edit_and_share': 'Edit and Share',
        'change_owner': 'Change Owner',
        # Classic shared folder permissions
        'no_permissions': 'No User Permissions',
        'manage_users': 'Can Manage Users',
        'manage_records': 'Can Manage Records',
        'manage_all': 'Can Manage Records and Users',
        # Nested Share Folder roles
        'viewer': 'Viewer (read-only)',
        'share-manager': 'Share Manager',
        'content-manager': 'Content Manager',
        'content-share-manager': 'Content & Share Manager',
        'full-manager': 'Full Manager',
        'owner': 'Transfer Ownership',
    }
    return mappings.get(permission, permission.replace('_', ' ').title())


DURATION_OPTIONS = [
    ("5m", "5 minutes", 300),
    ("10m", "10 minutes", 600),
    ("30m", "30 minutes", 1800),
    ("1h", "1 hour", 3600),
    ("4h", "4 hours", 14400),
    ("8h", "8 hours", 28800),
    ("24h", "24 hours", 86400),
    ("7d", "7 days", 604800),
    ("30d", "30 days", 2592000),
    ("90d", "90 days", 7776000),
    ("permanent", "No Expiration", None),
]


def parse_duration_to_seconds(duration_str: str) -> Optional[int]:
    """
    Convert duration string to seconds (None = permanent).
    """
    if duration_str == "permanent":
        return None
    for value, _, seconds in DURATION_OPTIONS:
        if value == duration_str:
            return seconds
    return 300  # Default: 5 minutes


def format_duration(duration_str: str) -> str:
    """
    Format duration string for display.
    """
    for value, label, _ in DURATION_OPTIONS:
        if value == duration_str:
            return label
    return '5 minutes'


def get_duration_options(exclude_permanent: bool = False) -> list:
    """
    Get standard duration options as ``(value, label)`` pairs.
    """
    return [
        (value, label) for value, label, _ in DURATION_OPTIONS
        if not (exclude_permanent and value == "permanent")
    ]


def resolve_approval_channel(config, keeper_client, requester_email: Optional[str]) -> str:
    """
    Resolve which Zoom channel an approval request should be posted to.

    With multi-channel approvers enabled, the requester's Keeper team decides
    the channel; otherwise (or with no matching team) the default approvals
    channel is used.
    """
    default_channel = config.zoom.approvals_channel_jid
    try:
        mc = config.multichannel_approver
        if not mc.enabled or not mc.teams:
            return default_channel

        if not requester_email:
            logger.info(
                "Multi-channel routing: requester email unknown; "
                f"using default channel {default_channel}"
            )
            return default_channel

        teams = keeper_client.get_user_teams(requester_email)
        for team_name in teams:
            channel = mc.teams.get(team_name)
            if channel:
                logger.info(
                    f"Multi-channel routing: {requester_email} -> team '{team_name}' -> {channel}"
                )
                return channel

        logger.info(
            f"Multi-channel routing: no mapped team for {requester_email}; "
            f"using default channel {default_channel}"
        )
        return default_channel
    except Exception as e:
        logger.error(f"Error resolving approval channel: {e}; using default channel")
        return default_channel
