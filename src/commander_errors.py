# -*- coding: utf-8 -*-
"""
Shared Commander Service Mode error helpers.
"""

from typing import Any, Dict, Optional

from .logger import logger


COMMAND_NOT_ALLOWED = "command_not_allowed"
COMMANDER_UNAUTHORIZED = "commander_unauthorized"
COMMANDER_SUBMIT_FAILED = "commander_submit_failed"


COMMAND_NOT_ALLOWED_MESSAGE = (
    "Commander rejected the command (HTTP 403).\n\n"
    "This usually means the command is not in the Zoom app's Commander "
    "Service Mode allowlist. Add it to the `service-create -c` command list "
    "used for this app instance and restart Commander Service Mode."
)


def submit_error(status_code: int) -> Dict[str, Any]:
    """
    Return a structured error payload for a failed executecommand-async submit.
    """
    if status_code == 403:
        return {
            "success": False,
            "error_code": COMMAND_NOT_ALLOWED,
            "error": COMMAND_NOT_ALLOWED_MESSAGE,
        }

    if status_code == 401:
        return {
            "success": False,
            "error_code": COMMANDER_UNAUTHORIZED,
            "error": (
                "Commander rejected the request (HTTP 401). Please verify the "
                "Commander Service Mode API key in zoom_config.yaml and restart the app."
            ),
        }

    return {
        "success": False,
        "error_code": COMMANDER_SUBMIT_FAILED,
        "error": f"Failed to submit command: HTTP {status_code}",
    }


def log_submit_warning(status_code: int, command_name: Optional[str] = None) -> None:
    """
    Log an admin-friendly message for read-only paths that keep returning their
    fallback values ([] / None / False).
    """
    prefix = (
        f"Commander rejected {command_name} command"
        if command_name
        else "Commander rejected command"
    )

    if status_code == 403:
        logger.error("%s: %s", prefix, COMMAND_NOT_ALLOWED_MESSAGE.replace("\n\n", " "))
        return

    if status_code == 401:
        logger.error(
            "%s: HTTP 401. Verify Commander Service Mode credentials and restart the app.",
            prefix,
        )
        return

    logger.error("%s: HTTP %s", prefix, status_code)
