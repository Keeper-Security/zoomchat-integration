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

"""
Emoji shortcodes for message text.

Cards are written with shortcodes (``":lock: Recommended"``). Zoom chatbot
markdown doesn't render shortcodes, so :func:`emojize` swaps them for the
emoji just before a message is sent. Unknown shortcodes are left as they are.
"""

import re
from typing import Any

SHORTCODES = {
    ":file_folder:": "\U0001F4C1",
    ":hourglass_flowing_sand:": "\u23F3",
    ":incoming_envelope:": "\U0001F4E8",
    ":information_source:": "\u2139\uFE0F",
    ":key:": "\U0001F511",
    ":link:": "\U0001F517",
    ":lock:": "\U0001F512",
    ":no_entry_sign:": "\U0001F6AB",
    ":open_file_folder:": "\U0001F4C2",
    ":warning:": "\u26A0\uFE0F",
    ":white_check_mark:": "\u2705",
    ":x:": "\u274C",
}

_SHORTCODE = re.compile(r":[a-z0-9_]+:")


def emojize(value: Any) -> Any:
    """Replace known shortcodes in every string of a message payload (dicts / lists / strings)."""
    if isinstance(value, str):
        return _SHORTCODE.sub(lambda m: SHORTCODES.get(m.group(0), m.group(0)), value)
    if isinstance(value, dict):
        return {key: emojize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [emojize(item) for item in value]
    return value
