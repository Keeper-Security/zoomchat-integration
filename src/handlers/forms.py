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

"""Helpers shared by the form cards (search results, Create New Record, create-secret)."""

from typing import Any, Dict, Iterable, List


def submitted_values(items: List[Dict[str, Any]], choice_prefixes: Iterable[str] = ()) -> Dict[str, str]:
    """
    Read a ``chat_message.submit`` payload's ``submit_items``.

    Returns ``action_id -> value`` for text inputs, and ``prefix -> full value``
    for radio / dropdown choices whose value starts with ``"<prefix>|"``
    (their ``action_id`` isn't reliable, so they're matched by value).
    """
    prefixes = tuple(choice_prefixes)
    values: Dict[str, str] = {}
    for item in items:
        for kind, data in item.items():
            if kind == "actionItem":
                continue
            # Dropdowns arrive as ``selectedItems``: a list of the chosen options
            for entry in (data if isinstance(data, list) else [data]):
                if not isinstance(entry, dict):
                    continue
                value = (entry.get("value")
                         or (entry.get("selected_option") or {}).get("value")
                         or (entry.get("selected_item") or {}).get("value") or "")
                if not isinstance(value, str):
                    continue
                prefix = next((p for p in prefixes if value.startswith(f"{p}|")), None)
                if prefix:
                    values[prefix] = value
                elif entry.get("action_id"):
                    values[entry["action_id"]] = value
    return values


def wants_generated_password(password: str) -> bool:
    """A blank password or ``$GEN`` means Commander generates one (``password=$GEN``)."""
    return not password or password.upper() == "$GEN"
