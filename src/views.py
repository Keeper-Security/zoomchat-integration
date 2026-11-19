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
Zoom chatbot message cards.

The approval card is rendered entirely from the stored
:class:`~src.models.AccessRequest`, so every select / button event just
updates the request and re-renders the card with ``edit_message``.

Interactive element values are ``"<action>|<approval_id>|<arg>"``.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

from .models import (
    AccessRequest,
    FOLDER_PERMANENT_ONLY_PERMISSIONS,
    KeeperFolder,
    KeeperRecord,
    NSFPermissionRole,
    PermissionLevel,
    PERMANENT_ONLY_PERMISSIONS,
    RequestStatus,
)
from .logger import logger
from .utils import (
    format_duration,
    format_permission_name,
    get_duration_options,
    is_pam_user_record_type,
    sanitize_hyperlinks,
    truncate_text,
)

# Default Keeper server domain
DEFAULT_KEEPER_DOMAIN = "keepersecurity.com"

APP_NAME = "Keeper Security"

# Interactive element actions
ACTION_APPROVE = "approve"
ACTION_DENY = "deny"
ACTION_SEARCH = "search"
ACTION_RESYNC = "resync"    # sync-down, then search again
ACTION_PICK = "pick"
ACTION_CHANGE_RECORD = "change"
SELECT_RECORD = "rec"
SELECT_PERMISSION = "perm"
SELECT_DURATION = "dur"
SELECT_ROTATE = "rot"
# Approver "Create New Record" form on the approval card
ACTION_NEW_RECORD = "newrec"
ACTION_NEW_RECORD_BACK = "newrecback"
ACTION_NEW_RECORD_SUBMIT = "newrecsub"
# Permission model is a pair of buttons: dropdowns and radios on a form card send no event until submit
ACTION_PERMISSION_MODEL = "nrvault"
SELECT_SELF_DESTRUCT = "nrsd"

CLASSIC_PERMISSION_OPTIONS: List[Tuple[str, str]] = [
    (PermissionLevel.VIEW_ONLY.value, "View Only"),
    (PermissionLevel.CAN_EDIT.value, "Can Edit"),
    (PermissionLevel.CAN_SHARE.value, "Can Share"),
    (PermissionLevel.EDIT_AND_SHARE.value, "Edit and Share"),
    (PermissionLevel.CHANGE_OWNER.value, "Change Owner"),
]

NSF_PERMISSION_OPTIONS: List[Tuple[str, str]] = [
    (NSFPermissionRole.VIEWER.value, "Viewer (read-only)"),
    (NSFPermissionRole.SHARE_MANAGER.value, "Share Manager"),
    (NSFPermissionRole.CONTENT_MANAGER.value, "Content Manager"),
    (NSFPermissionRole.CONTENT_SHARE_MANAGER.value, "Content & Share Manager"),
    (NSFPermissionRole.FULL_MANAGER.value, "Full Manager"),
    (NSFPermissionRole.TRANSFER_OWNER.value, "Transfer Ownership"),
]

FOLDER_PERMISSION_OPTIONS: List[Tuple[str, str]] = [
    (PermissionLevel.NO_PERMISSIONS.value, "No User Permissions"),
    (PermissionLevel.MANAGE_USERS.value, "Can Manage Users"),
    (PermissionLevel.MANAGE_RECORDS.value, "Can Manage Records"),
    (PermissionLevel.MANAGE_ALL.value, "Can Manage Records and Users"),
]

# Nested Share Folders can't be transferred, so no Transfer Ownership role
NSF_FOLDER_PERMISSION_OPTIONS: List[Tuple[str, str]] = [
    option for option in NSF_PERMISSION_OPTIONS if option[0] != NSFPermissionRole.TRANSFER_OWNER.value
]

# One-time share links are view-only or editable (Commander --editable)
ONE_TIME_SHARE_PERMISSION_OPTIONS: List[Tuple[str, str]] = [
    (PermissionLevel.VIEW_ONLY.value, "View Only"),
    (PermissionLevel.CAN_EDIT.value, "Can Edit"),
]

Item = Union[KeeperRecord, KeeperFolder]

# Card accent colours (Zoom client palette)
COLOR_PENDING = "#0E72ED"
COLOR_PROCESSING = "#F5A623"
COLOR_APPROVED = "#00A651"
COLOR_DENIED = "#E02828"
COLOR_NEUTRAL = "#747487"

# Search results kept and listed: approval cards and create-secret folder dropdowns
# (the real total is still shown, and Find / Search reaches the rest). Must stay
# under 100: Zoom rejects a whole message whose dropdown has more entries.
MAX_SEARCH_RESULTS = 20
DIVIDER = {"type": "divider", "style": {"bold": False, "dotted": False, "color": "#DFE3E8"}}

ROTATE_OPTIONS: List[Tuple[str, str]] = [
    ("yes", "Yes - rotate credentials when access expires"),
    ("no", "No - do not rotate"),
]

PERMISSION_MODEL_OPTIONS: List[Tuple[str, str]] = [
    ("nsf", "Nested Share Folder record"),
    ("classic", "Classic record"),
]

# "Self-destruct" choices for approver-created Classic records
SELF_DESTRUCT_DURATIONS = ("5m", "10m", "30m", "1h", "24h", "7d", "30d", "90d")


def encode_value(action: str, approval_id: str, arg: str = "") -> str:
    return f"{action}|{approval_id}|{arg}"


def decode_value(value: str) -> Tuple[str, str, str]:
    parts = (value or "").split("|", 2)
    while len(parts) < 3:
        parts.append("")
    return parts[0], parts[1], parts[2]


# ----------------------------------------------------------------------
# Generic content helpers
# ----------------------------------------------------------------------

def text_content(text: str, title: str = APP_NAME, sub_head: Optional[str] = None) -> Dict[str, Any]:
    """Simple card with a header and one markdown message."""
    return {"head": _head(title, sub_head), "body": [_message(text)]}


def notice_content(text: str, level: str = "ERROR", title: str = APP_NAME) -> Dict[str, Any]:
    """
    Reply whose first paragraph is a highlighted note (``NOTE_ERROR`` / ``NOTE_WARN`` /
    ``NOTE_INFO``); anything after the first blank line is shown as normal text.
    """
    summary, _, details = text.partition("\n\n")
    body = [_note(summary.replace("*", "").strip(), level)]
    if details.strip():
        body.append(_message(_keep_underscores(details.strip())))
    return {"head": _head(title), "body": body}


def _select(text: str, options: List[Tuple[str, str]], action: str,
            approval_id: str, selected_value: Optional[str]) -> Dict[str, Any]:
    items = [
        {"text": label, "value": encode_value(action, approval_id, value)}
        for value, label in options
    ]
    block: Dict[str, Any] = {"type": "select", "text": text, "select_items": items}
    for item, (value, _) in zip(items, options):
        if value == selected_value:
            block["selected_item"] = dict(item)
            break
    return block


def _fields(pairs: List[Tuple[str, str]], wide: Tuple[str, ...] = ()) -> Dict[str, Any]:
    """Key/value grid; keys in ``wide`` take a full row."""
    return {
        "type": "fields",
        "items": [{"key": k, "value": v or "-", "short": k not in wide} for k, v in pairs],
    }


def _section(color: str, items: List[Dict[str, Any]], footer: Optional[str] = None) -> Dict[str, Any]:
    """Group items behind a coloured sidebar."""
    block: Dict[str, Any] = {"type": "section", "sidebar_color": color, "sections": items}
    if footer:
        block["footer"] = footer
    return block


def _message(text: str) -> Dict[str, Any]:
    return {"type": "message", "text": text}


# Zoom ``alert`` levels: a light tinted box with a matching icon (Zoom rejects WARNING, NOTICE, ...).
# Zoom currently draws WARN like INFO (blue), so warnings also start with a bold "Warning:".
# Alert text renders *bold* markdown.
NOTE_INFO = "INFO"
NOTE_SUCCESS = "SUCCESS"
NOTE_WARN = "WARN"
NOTE_ERROR = "ERROR"


_CODE_SPAN = re.compile(r"(`[^`]*`)")


def _keep_underscores(text: str) -> str:
    """
    Escape ``_`` as ``\\_`` outside code spans. Card text is markdown, so a Commander code
    like ``not_allowed_one_time_share`` (or a record UID) would otherwise lose underscores to italics.
    """
    return "".join(part if part.startswith("`") else part.replace("_", "\\_")
                   for part in _CODE_SPAN.split(text))


def _note(text: str, level: str = NOTE_INFO, closeable: bool = False) -> Dict[str, Any]:
    """Highlighted note, warning or error. Plain text: the alert adds its own icon."""
    text = _keep_underscores(text)
    if level == NOTE_WARN:
        text = f"*Warning:* {text}"
    return {"type": "alert", "text": text, "level": level, "closeable": closeable}


def _input_warning(text: str) -> Dict[str, Any]:
    """
    One-off "fix your input" warning. The user dismisses it with x: redrawing the card to
    hide it on a timer would also wipe anything they had typed since.
    """
    return _note(text, NOTE_WARN, closeable=True)


def _buttons(items: List[Tuple[str, str, str]]) -> Dict[str, Any]:
    """``items``: (label, value, style) with style Primary / Danger / Default."""
    return {"type": "actions", "items": [{"text": t, "value": v, "style": s} for t, v, s in items]}


def _head(title: str, sub_head: Optional[str] = None) -> Dict[str, Any]:
    head: Dict[str, Any] = {"text": title, "style": {"bold": True}}
    if sub_head:
        head["sub_head"] = {"text": sub_head}
    return head


def _record_type_label(record_type: str) -> str:
    return (record_type or "login").replace('_', ' ').title()


# ----------------------------------------------------------------------
# Approval card state helpers
# ----------------------------------------------------------------------

def default_permission(item: Item) -> str:
    """Minimum access by default (View Only / No User Permissions / NSF Viewer)."""
    if item.is_nsf:
        return NSFPermissionRole.VIEWER.value
    if isinstance(item, KeeperFolder):
        return PermissionLevel.NO_PERMISSIONS.value
    return PermissionLevel.VIEW_ONLY.value


def permission_options(item: Item) -> List[Tuple[str, str]]:
    if isinstance(item, KeeperFolder):
        return NSF_FOLDER_PERMISSION_OPTIONS if item.is_nsf else FOLDER_PERMISSION_OPTIONS
    return NSF_PERMISSION_OPTIONS if item.is_nsf else CLASSIC_PERMISSION_OPTIONS


def is_permanent_only(item: Item, permission: Optional[str]) -> bool:
    """Permissions that ignore the duration selector."""
    if isinstance(item, KeeperFolder):
        return not item.is_nsf and permission in {p.value for p in FOLDER_PERMANENT_ONLY_PERMISSIONS}
    if item.is_nsf:
        return permission == NSFPermissionRole.TRANSFER_OWNER.value
    return permission in {p.value for p in PERMANENT_ONLY_PERMISSIONS}


def is_pam_target(item: Optional[Item]) -> bool:
    """PAM User records and PAM shared folders (Classic only) support rotate-on-expire."""
    if not item or item.is_nsf:
        return False
    if isinstance(item, KeeperFolder):
        return item.is_pam
    return is_pam_user_record_type(item.record_type)


def request_permission_options(request: AccessRequest, item: Item) -> List[Tuple[str, str]]:
    if request.is_one_time_share:
        return ONE_TIME_SHARE_PERMISSION_OPTIONS
    return permission_options(item)


# One-time share link expirations ("No Expiration" removed: links always expire)
ONE_TIME_SHARE_DURATIONS = ("5m", "10m", "30m", "1h", "4h", "8h", "24h", "7d", "30d")


def request_duration_options(request: AccessRequest, item: Item) -> List[Tuple[str, str]]:
    """Duration dropdown options; PAM rotate-on-expire needs an expiry."""
    if request.is_one_time_share:
        return [opt for opt in get_duration_options() if opt[0] in ONE_TIME_SHARE_DURATIONS]
    return get_duration_options(exclude_permanent=is_pam_target(item))


def request_is_permanent_only(request: AccessRequest, item: Item, permission: Optional[str]) -> bool:
    return not request.is_one_time_share and is_permanent_only(item, permission)


def can_create_record(request: AccessRequest) -> bool:
    """"Create New Record" is offered only for description-based record requests (not folders or OTS)."""
    return not request.is_uid and not request.is_folder and not request.is_one_time_share


def self_destruct_for(request: AccessRequest, item: Optional[Item]) -> Optional[str]:
    """Self-destruct duration when ``item`` is the Classic record the approver created with one."""
    if item and request.self_destruct and item.uid == request.created_record_uid and not item.is_nsf:
        return request.self_destruct
    return None


def select_item(request: AccessRequest, item: Item):
    """Make ``item`` the record/folder being approved and reset choices to safe defaults."""
    request.selected = item.to_dict()
    request.permission = default_permission(item)
    if request.is_one_time_share:
        request.duration = ONE_TIME_SHARE_DURATIONS[0]
    elif request.duration == "permanent" and is_pam_target(item):
        request.duration = "5m"
    request.banner = None


# ----------------------------------------------------------------------
# Approval card
# ----------------------------------------------------------------------

def _noun(request: AccessRequest) -> str:
    return request.item_noun.capitalize()


def _card_title(request: AccessRequest) -> str:
    if request.is_one_time_share:
        return "One-Time Share Request"
    return f"{_noun(request)} Access Request"


def _request_fields(request: AccessRequest) -> Dict[str, Any]:
    return _fields([
        ("Requester", request.requester_name),
        ("Request ID", request.approval_id),
        (_noun(request), sanitize_hyperlinks(request.identifier)),
        ("Requested", request.created_at),
        ("Justification", sanitize_hyperlinks(request.justification)),
    ], wide=("Justification",))


def _item_details(item: Item) -> List[Dict[str, Any]]:
    if isinstance(item, KeeperFolder):
        folder_type = "Nested Share Folder" if item.is_nsf else "Shared Folder"
        if item.is_pam:
            folder_type += " (PAM User records)"
        return [
            {"type": "message", "text": "Folder Details", "style": {"bold": True}},
            _fields([("Name", item.name), ("Type", folder_type), ("UID", item.uid)]),
        ]
    record = item
    notes = record.notes or ""
    return [
        {"type": "message", "text": "Record Details", "style": {"bold": True}},
        _fields([
            ("Title", record.title),
            ("Type", _record_type_label(record.record_type)),
            ("UID", record.uid),
            ("Folder", "Nested Share Folder" if record.is_nsf else "Classic Share Folder"),
            ("Description", truncate_text(notes, 200) if notes else "No description"),
        ], wide=("Description",)),
    ]


def _result_label(item: Dict[str, Any]) -> str:
    title = sanitize_hyperlinks(truncate_text(item.get("title") or item.get("name") or "Untitled", 60))
    return f"{_folder_badge(bool(item.get('is_nsf')))} {title} {PREFIX_SEPARATOR} UID: {item.get('uid', '')}"


def _search_box(request: AccessRequest) -> List[Dict[str, Any]]:
    """Editable "Search for" box: Zoom dropdowns can't be filtered, so the approver searches again."""
    return [
        _text_input("search_query", f"Search {request.item_noun}s",
                    f"{_noun(request)} name or description",
                    value=truncate_text(request.current_query, 200), max_length=200),
        {"type": "actions", "items": [
            {"text": "Search", "value": encode_value(ACTION_SEARCH, request.approval_id), "style": "Primary",
             "submit": True},
            {"text": "Re-Sync Vault", "value": encode_value(ACTION_RESYNC, request.approval_id), "style": "Default",
             "submit": True},
        ]},
    ]


def _search_results_section(request: AccessRequest, notice: Optional[str] = None) -> Dict[str, Any]:
    """Results dropdown (first ``MAX_SEARCH_RESULTS``) with the search box, submitted as a Zoom form card."""
    aid = request.approval_id
    results = request.search_results[:MAX_SEARCH_RESULTS]
    total = max(request.search_total, len(results))
    select_items = [{"text": _result_label(item), "value": encode_value(SELECT_RECORD, aid, str(idx))}
                    for idx, item in enumerate(results)]
    select: Dict[str, Any] = {"type": "select", "text": f"Select a {request.item_noun}", "select_items": select_items}
    if len(select_items) == 1:
        select["selected_item"] = dict(select_items[0])
    buttons = [
        {"text": f"Use Selected {_noun(request)}", "value": encode_value(ACTION_PICK, aid), "style": "Primary",
         "submit": True},
    ]
    if can_create_record(request):
        buttons.append({"text": "Create New Record", "value": encode_value(ACTION_NEW_RECORD, aid),
                        "style": "Primary"})
    buttons.append({"text": "Deny", "value": encode_value(ACTION_DENY, aid), "style": "Danger"})

    summary = f"{total} {request.item_noun}(s) match \"{sanitize_hyperlinks(request.current_query)}\""
    if total > len(results):
        summary += f"; showing the first {len(results)}. Change the search to narrow it down."
    else:
        summary += "."
    items: List[Dict[str, Any]] = _search_box(request) + [select, _note(summary)]
    if notice:
        items.append(_input_warning(notice))
    items.append({"type": "actions", "items": buttons})
    if can_create_record(request):
        items.append(_note("Can't find it? Create a new record and share it."))
    return _section(COLOR_PENDING, items)


def _pending_card(request: AccessRequest, form_prefill: Optional[Dict[str, str]] = None,
                  notice: Optional[str] = None) -> Dict[str, Any]:
    aid = request.approval_id
    record = request.selected_item
    noun = request.item_noun
    card: Dict[str, Any] = {"head": _head(_card_title(request), f"from {request.requester_name}")}
    body: List[Dict[str, Any]] = [_section(COLOR_PENDING, [_request_fields(request)]), DIVIDER]
    card["body"] = body
    deny = ("Deny", encode_value(ACTION_DENY, aid), "Danger")

    if request.creating_record and can_create_record(request):
        return _create_record_form_card(request, card, form_prefill)

    # Description request: approver must search and pick the record/folder first
    if not request.is_uid and not record:
        if not request.searched:
            items = [_message(f"*Action Required:* search the vault for the requested {noun}.")]
            if request.banner:
                # Only set when Commander rejected the sync/search, so nothing was searched
                items.append(_note(f"Search failed: {request.banner}", NOTE_ERROR))
            items.append(_buttons([(f"Search {_noun(request)}s", encode_value(ACTION_SEARCH, aid), "Primary"),
                                   ("Re-Sync Vault", encode_value(ACTION_RESYNC, aid), "Default"), deny]))
            body.append(_section(COLOR_PROCESSING if request.banner else COLOR_PENDING, items))
            return card

        if not request.search_results:
            items = _search_box(request) + [_note(
                f"No {noun}s found matching \"{request.current_query}\". Change the search, "
                f"ask the requester for the {noun} UID, or deny the request.", NOTE_WARN,
            )]
            if request.banner:
                items.append(_note(request.banner, NOTE_WARN))
            if notice:
                items.append(_input_warning(notice))
            buttons = []
            if can_create_record(request):
                buttons.append(("Create New Record", encode_value(ACTION_NEW_RECORD, aid), "Primary"))
            items.append(_buttons(buttons + [deny]))
            if can_create_record(request):
                items.append(_note("Can't find it? Create a new record and share it."))
            card["settings"] = {"form": True}
            body.append(_section(COLOR_PROCESSING, items))
            return card

        card["settings"] = {"form": True}
        body.append(_search_results_section(request, notice))
        if request.banner:
            body.append(_note(request.banner, NOTE_WARN))
        return card

    controls: List[Dict[str, Any]] = []
    self_destruct = self_destruct_for(request, record)
    if record:
        body.append(_section(COLOR_PENDING, _item_details(record)))
        body.append(DIVIDER)

    if self_destruct:
        # The approver chose these when creating the record, so no selectors
        controls.append(_message("*Self-Destruct Record Settings*"))
        controls.append(_note(
            f"Shared directly to the requester's vault with View Only access. "
            f"The record auto-deletes after {format_duration(self_destruct)}."
        ))
    elif record:
        if request.is_one_time_share:
            label = "Link Permission"
        else:
            label = "Permission Level (Nested Share Folder)" if record.is_nsf else "Permission Level"
        controls.append(_select(
            label, request_permission_options(request, record), SELECT_PERMISSION, aid, request.permission,
        ))
        if request_is_permanent_only(request, record, request.permission):
            controls.append(_note(
                f"{format_permission_name(request.permission)} is always permanent (no time limit)."
            ))
        else:
            pam = is_pam_target(record)
            controls.append(_select(
                "Link Expires In" if request.is_one_time_share else "Grant Access For",
                request_duration_options(request, record), SELECT_DURATION, aid, request.duration,
            ))
            if pam:
                controls.append(_select(
                    "PAM credential rotation", ROTATE_OPTIONS, SELECT_ROTATE, aid,
                    "yes" if request.rotate_on_expire else "no",
                ))
                controls.append(_note(
                    "PAM User folder: credentials in this folder rotate when time-limited access expires "
                    "(rotation must be configured on the underlying records)."
                    if request.is_folder else
                    "PAM User record: credentials rotate when time-limited access expires "
                    "(rotation must be configured on the record)."
                ))

    buttons = [("Approve", encode_value(ACTION_APPROVE, aid), "Primary"), deny]
    if not request.is_uid:
        buttons.append((f"Change {_noun(request)}", encode_value(ACTION_CHANGE_RECORD, aid), "Default"))
    controls.append(_buttons(buttons))
    body.append(_section(COLOR_PENDING, controls))

    if request.banner:
        body.append(_note(f"Last attempt failed: {request.banner}", NOTE_ERROR))
    return card


def _create_record_form_card(request: AccessRequest, card: Dict[str, Any],
                             prefill: Optional[Dict[str, str]]) -> Dict[str, Any]:
    """
    "Create New Record" form on the approval card. There is no folder choice:
    Commander creates the record in its default location, then the approver
    shares it with the requester.
    """
    aid = request.approval_id
    prefill = prefill or {}
    model = "classic" if request.new_record_classic else "nsf"
    model_hint = {
        "nsf": "Role-based sharing.",
        "classic": "Classic permissions, with an optional self-destruct timer.",
    }[model]

    if request.banner:
        card["body"].append(_note(f"Could not create record: {request.banner}", NOTE_ERROR))
    card["body"].append(_section(COLOR_PENDING, [
        _message(f"*Create New Record* for {request.requester_name}\n"
                 f"You'll approve sharing once it's created."),
        _message("*1. Permission model*"),
        _buttons([(label, encode_value(ACTION_PERMISSION_MODEL, aid, value),
                   "Primary" if value == model else "Default")
                  for value, label in PERMISSION_MODEL_OPTIONS]),
        _note(f"{model_hint} Pick this first: switching clears the fields below."),
    ]))

    items: List[Dict[str, Any]] = [
        _message("*2. Record details*"),
        _text_input("nr_title", "Title (required)", "Record title",
                    value=prefill.get("title", truncate_text(request.current_query, 500))),
        _text_input("nr_login", "Login (required)", "Email or username", value=prefill.get("login", "")),
        _text_input("nr_password", "Password", PASSWORD_PLACEHOLDER),
        _note(PASSWORD_HINT),
        _text_input("nr_url", "Website Address", "https://", value=prefill.get("url", "")),
        _text_input("nr_notes", "Notes", "Optional notes", multiline=True, max_length=2000,
                    value=prefill.get("notes", "")),
    ]
    if model == "classic":
        self_destruct_options = [("off", "Off")] + [
            (value, label) for value, label in get_duration_options() if value in SELF_DESTRUCT_DURATIONS
        ]
        items += [
            _select("Self-destruct", self_destruct_options, SELECT_SELF_DESTRUCT, aid,
                    prefill.get("self_destruct", "off")),
            _note("Deletes the record from the vault after this time. The requester gets View Only access."),
        ]
    items.append({"type": "actions", "items": [
        {"text": "Create Record", "value": encode_value(ACTION_NEW_RECORD_SUBMIT, aid), "style": "Primary",
         "submit": True},
        {"text": "Back", "value": encode_value(ACTION_NEW_RECORD_BACK, aid), "style": "Default"},
    ]})
    card["settings"] = {"form": True}
    card["body"].append(_section(COLOR_PENDING, items))
    return card


def build_searching_card(request: AccessRequest,
                         text: str = "*Syncing the vault and searching...*") -> Dict[str, Any]:
    """Approval card while Commander works (vault sync / search / record creation), controls hidden."""
    return {
        "head": _head(_card_title(request), f"from {request.requester_name}"),
        "body": [
            _section(COLOR_PENDING, [_request_fields(request)]),
            DIVIDER,
            _section(COLOR_PROCESSING, [_message(text)]),
        ],
    }


def _status_section(color: str, title: str, lines: List[str], footer: str,
                    level: Optional[str] = None) -> Dict[str, Any]:
    """Outcome block: the heading in bold, or as a highlighted note when ``level`` is set."""
    if level:
        items = [_note(title, level)] + ([_message("\n".join(lines))] if lines else [])
        return _section(color, items, footer=footer)
    text = f"*{title}*" + "".join(f"\n{line}" for line in lines)
    return _section(color, [_message(text)], footer=footer)


def build_approval_card(request: AccessRequest, form_prefill: Optional[Dict[str, str]] = None,
                        notice: Optional[str] = None) -> Dict[str, Any]:
    """
    Render the approvals-channel card for the request's current status.
    ``form_prefill`` re-fills the Create New Record form after a failed attempt.
    """
    status = request.status
    record = request.selected_item
    title = _card_title(request)
    sub_head = f"from {request.requester_name}"

    if status == RequestStatus.PENDING:
        return _pending_card(request, form_prefill, notice)

    # Resolved cards keep the request and item, drop the controls and add a status section
    color = {
        RequestStatus.PROCESSING: COLOR_PROCESSING,
        RequestStatus.APPROVED: COLOR_APPROVED,
        RequestStatus.INVITATION_SENT: COLOR_APPROVED,
    }.get(status, COLOR_DENIED)
    body: List[Dict[str, Any]] = [_section(color, [_request_fields(request)]), DIVIDER]
    if record:
        body += [_section(color, _item_details(record)), DIVIDER]

    if status == RequestStatus.PROCESSING:
        body.append(_status_section(
            COLOR_PROCESSING, "Granting access...",
            [f"Approved by {request.approver_name}. This may take a few seconds."],
            footer="Keeper Security",
        ))
        return {"head": _head(title, "Granting access..."), "body": body}

    if status == RequestStatus.APPROVED and request.is_one_time_share:
        body.append(_status_section(
            COLOR_APPROVED, "One-Time Share Link Created",
            ["The link was sent to the requester by DM.",
             f"Link expires on *{request.expires_at}*",
             f"*Permission:* {format_permission_name(request.permission or '')}"],
            footer=f"Approved by {request.approver_name} • {request.resolved_at}", level=NOTE_SUCCESS,
        ))
        return {"head": _head("One-Time Share Request Approved", sub_head), "body": body}

    if status == RequestStatus.APPROVED:
        if request.duration == "permanent" or (record and is_permanent_only(record, request.permission)):
            lines = ["Access remains active indefinitely"]
            heading = "Access Granted (No Expiration)"
        else:
            lines = [f"Access will expire on *{request.expires_at}*"]
            heading = "Temporary Access Granted"
        lines.append(f"*Permission:* {format_permission_name(request.permission or '')}")
        if request.rotate_scheduled:
            lines.append("*PAM credentials will rotate* when access expires")
        self_destruct = self_destruct_for(request, record)
        if self_destruct:
            lines.append(f"\n*Self-Destruct Record*\nRecord will auto-delete after {format_duration(self_destruct)}")
        body.append(_status_section(
            COLOR_APPROVED, heading, lines,
            footer=f"Approved by {request.approver_name} • {request.resolved_at}", level=NOTE_SUCCESS,
        ))
        approved_title = "Self-Destruct Record Access Approved" if self_destruct else f"{title} Approved"
        return {"head": _head(approved_title, sub_head), "body": body}

    if status == RequestStatus.INVITATION_SENT:
        body.append(_status_section(
            COLOR_APPROVED, "Share Invitation Sent",
            ["A share invitation has been sent to the requester's email.",
             f"They must accept it and create a Keeper account to access this {request.item_noun}.",
             f"*Permission:* {format_permission_name(request.permission or '')}"],
            footer=f"Approved by {request.approver_name} • {request.resolved_at}", level=NOTE_SUCCESS,
        ))
        return {"head": _head(title, sub_head), "body": body}

    # DENIED / OWNER / FAILED: the outcome as a highlighted note (owner = nothing to grant)
    level = NOTE_WARN if status == RequestStatus.OWNER else NOTE_ERROR
    body.append(_section(COLOR_DENIED, [_note(request.status_text or status, level)],
                         footer=f"Updated {request.resolved_at}"))
    return {"head": _head(title, sub_head), "body": body}


# ----------------------------------------------------------------------
# Approvals channel
# ----------------------------------------------------------------------

def post_approval_request(zoom_client, request: AccessRequest) -> str:
    """Post the approval card to ``request.channel_jid``; returns the message ID."""
    return zoom_client.send_message(
        to_jid=request.channel_jid,
        content=build_approval_card(request),
        user_jid=request.requester_jid,
        account_id=request.account_id,
    )


def update_approval_card(zoom_client, request: AccessRequest,
                         form_prefill: Optional[Dict[str, str]] = None, notice: Optional[str] = None) -> None:
    """Re-render the approval card in place; ``notice`` is a one-off warning shown on it (not stored)."""
    if not request.message_id:
        logger.warning(f"No message_id for {request.approval_id}; cannot update card")
        return
    zoom_client.edit_message(
        message_id=request.message_id,
        to_jid=request.channel_jid,
        content=build_approval_card(request, form_prefill, notice),
        user_jid=request.requester_jid,
        account_id=request.account_id,
    )


def now_display() -> str:
    return datetime.now().strftime('%B %d, %Y at %I:%M %p')


# ----------------------------------------------------------------------
# Requester DMs
# ----------------------------------------------------------------------

def _link(url: str) -> str:
    """
    Zoom markdown link. Inside ``<...>`` the URL isn't parsed as markdown, so ``_`` in a
    share key or record UID can't turn part of it into italics and cut the link short.
    """
    return f"<{url}>"


def get_vault_deep_link(uid: str, server_domain: str = DEFAULT_KEEPER_DOMAIN, is_folder: bool = False) -> str:
    """Keeper vault deep link for a record or shared folder."""
    if is_folder:
        return f"https://{server_domain}/vault/#shared_folder/{uid}"
    return f"https://{server_domain}/vault/#detail/{uid}"


def _dm_title(request: AccessRequest, outcome: str) -> str:
    """Requester DM title, e.g. "Record Access Granted" / "One-Time Share Denied"."""
    if request.is_one_time_share:
        return f"One-Time Share {outcome}"
    return f"{_noun(request)} Access {outcome}"


def _requested_fields(request: AccessRequest, item_title: Optional[str] = None) -> Dict[str, Any]:
    noun = "Record" if request.is_one_time_share else _noun(request)
    return _fields([
        ("Request ID", request.approval_id),
        (noun, sanitize_hyperlinks(item_title or request.identifier)),
    ])


def build_request_submitted_content(request: AccessRequest) -> Dict[str, Any]:
    after = ("the one-time share link will be sent to you here" if request.is_one_time_share
             else "you'll get the access details here")
    return {
        "head": _head(_dm_title(request, "Request Submitted")),
        "body": [
            _fields([
                ("Request ID", request.approval_id),
                ("Record" if request.is_one_time_share else _noun(request), sanitize_hyperlinks(request.identifier)),
                ("Justification", sanitize_hyperlinks(request.justification)),
            ], wide=("Justification",)),
            _note(f"Sent to the approvers channel. Once approved, {after}."),
        ],
    }


def build_access_granted_content(
    request: AccessRequest,
    server_domain: str = DEFAULT_KEEPER_DOMAIN,
) -> Dict[str, Any]:
    item = request.selected_item
    uid = item.uid if item else request.identifier
    title = item.title if item else uid
    body: List[Dict[str, Any]] = [
        _note(f"Approved by {request.approver_name}", NOTE_SUCCESS),
        _fields([
            ("Request ID", request.approval_id),
            (_noun(request), title),
            ("Permission", format_permission_name(request.permission or "")),
            ("Expires", request.expires_at or format_duration(request.duration)),
        ]),
        _message(f"Open in Vault: {_link(get_vault_deep_link(uid, server_domain, request.is_folder))}"),
    ]
    self_destruct = self_destruct_for(request, item)
    if self_destruct:
        body.append(_note(f"Self-destruct record: it will automatically delete from the vault after "
                          f"{format_duration(self_destruct)}."))
    return {"head": _head(_dm_title(request, "Granted")), "body": body}


def build_share_link_content(request: AccessRequest, share_url: str) -> Dict[str, Any]:
    """DM with the one-time share link."""
    item = request.selected_item
    return {
        "head": _head("One-Time Share Link Created"),
        "body": [
            _fields([
                ("Request ID", request.approval_id),
                ("Record", item.title if item else request.identifier),
                ("Permission", format_permission_name(request.permission or "")),
                ("Expires", request.expires_at or format_duration(request.duration)),
            ]),
            _message(f"*Share Link:*\n{_link(share_url)}"),
            _note(
                "\n• Keep this link safe\n"
                "• Opens on one device only\n"
                "• Expires after first use or when the time limit is reached\n"
                "• Share it only through secure channels\n"
                "• Never post it in Zoom channels\n"
                "• Keep it confidential",
                NOTE_WARN,
            ),
        ],
    }


def build_access_denied_content(request: AccessRequest) -> Dict[str, Any]:
    return {
        "head": _head(_dm_title(request, "Denied")),
        "body": [
            _note(f"Denied by {request.approver_name}", NOTE_ERROR),
            _requested_fields(request),
            _message("If you think this is a mistake, contact your manager or the security team."),
        ],
    }


def build_invitation_sent_content(request: AccessRequest) -> Dict[str, Any]:
    item = request.selected_item
    noun = request.item_noun
    return {
        "head": _head("Share Invitation Sent"),
        "body": [
            _note(f"Approved by {request.approver_name}. You don't have a Keeper account yet, so a share "
                  f"invitation has been sent to your email."),
            _requested_fields(request, item.title if item else None),
            _message(
                "*Next steps:*\n"
                "1. Check your email for the Keeper invitation\n"
                "2. Accept it and create your Keeper account\n"
                f"3. The {noun} will then be shared with you automatically"
            ),
        ],
    }


# ----------------------------------------------------------------------
# Create secret (form cards in the user's 1:1 chat with the bot)
# ----------------------------------------------------------------------

CS_FOLDER = "csf"        # dropdown option: shared folder chosen
CS_FOLDER_FIND = "csffind"  # submit: search the shared folders
CS_FOLDER_SYNC = "csfsync"  # submit: sync-down, then search the shared folders
CS_NEXT = "csnext"       # submit: folder step
CS_SUBFOLDER = "cssub"   # dropdown option: target subfolder
CS_CREATE = "cscreate"   # submit: record form
CS_FIND = "csfind"       # submit: narrow the subfolder dropdown
CS_SUB_SYNC = "cssync"   # submit: sync-down, then reload the subfolders
CS_CANCEL = "cscancel"
CS_BACK = "csback"       # button: step 2 back to the shared folder step

CREATE_SECRET_TITLE = "Create Secret"
# Shared by the create-secret and Create New Record forms. Zoom draws inputs at a fixed
# width, so placeholders stay short enough to show in full.
PASSWORD_PLACEHOLDER = "Leave blank to auto-generate"
PASSWORD_HINT = "*Recommended:* auto-generated passwords never pass through Zoom; typed ones do."


def encode_folder(action: str, uid: str, is_nsf: bool, name: str = "") -> str:
    return encode_value(action, "", f"{uid}|{int(bool(is_nsf))}|{name}")


def decode_folder(value: str) -> Tuple[str, str, bool, str]:
    """``(action, uid, is_nsf, name)`` from :func:`encode_folder`."""
    action, _, arg = decode_value(value)
    uid, nsf, name = (arg.split("|", 2) + ["", "", ""])[:3]
    return action, uid, nsf == "1", name


# Heavy vertical bar between dropdown parts (type, name, UID): option text is plain (no bold),
# so a heavier glyph sets the parts apart
PREFIX_SEPARATOR = "\u2503"


def _folder_badge(is_nsf: bool) -> str:
    """Dropdown prefix, e.g. ``"[NSF] ┃"``: option text is plain, so the type is spelled out."""
    return f"{'[NSF]' if is_nsf else '[Classic]'} {PREFIX_SEPARATOR}"


def build_create_secret_status(text: str, level: Optional[str] = None) -> Dict[str, Any]:
    """Status card; with ``level`` the text is shown as a highlighted note (e.g. ``NOTE_ERROR``)."""
    if level:
        return {"head": _head(CREATE_SECRET_TITLE), "body": [_note(text, level)]}
    return text_content(text, title=CREATE_SECRET_TITLE)


def build_create_secret_folder_card(folders: List[Dict[str, Any]], find: str = "",
                                    notice: Optional[str] = None) -> Dict[str, Any]:
    """
    Step 1: search box + dropdown of the user's shared folders. Zoom sends a dropdown
    choice only with a button press, so Next loads the subfolders (step 2).
    """
    find = find.strip()
    ordered = sorted(folders, key=lambda f: f["name"].lower())
    matches = [f for f in ordered if find.lower() in f["name"].lower()]
    shown = matches[:MAX_SEARCH_RESULTS]
    items: List[Dict[str, Any]] = [
        _text_input("cs_folder_find", "Find shared folder", "Part of a folder name", value=find, max_length=100),
        {"type": "actions", "items": [
            {"text": "Search", "value": encode_value(CS_FOLDER_FIND, ""), "style": "Primary", "submit": True},
            {"text": "Re-Sync Vault", "value": encode_value(CS_FOLDER_SYNC, ""), "style": "Default", "submit": True},
        ]},
    ]
    if shown:
        select_items = [
            {"text": f"{_folder_badge(f['is_nsf'])} {truncate_text(f['name'], 80)}",
             "value": encode_folder(CS_FOLDER, f["uid"], f["is_nsf"], truncate_text(f["name"], 100))}
            for f in shown
        ]
        select: Dict[str, Any] = {"type": "select", "text": "Shared folder", "select_items": select_items}
        if len(select_items) == 1:
            select["selected_item"] = dict(select_items[0])
        items.append(select)
    if find and not matches:
        items.append(_note(f"No shared folders match \"{find}\". Try another name.", NOTE_WARN))
    elif find:
        items.append(_note(f"{len(matches)} of {len(ordered)} shared folder(s) match \"{find}\""
                           + (f"; showing the first {len(shown)}." if len(shown) < len(matches) else ".")))
    elif len(shown) < len(matches):
        items.append(_note(f"Showing the first {len(shown)} of {len(matches)} shared folders (A to Z). "
                           f"Use Find to reach the rest."))
    if notice:
        items.append(_input_warning(notice))
    items.append({"type": "actions", "items": [
        {"text": "Next", "value": encode_value(CS_NEXT, ""), "style": "Primary", "submit": True},
        {"text": "Cancel", "value": encode_value(CS_CANCEL, ""), "style": "Danger"},
    ]})
    return {
        "settings": {"form": True},
        "head": _head(CREATE_SECRET_TITLE, "Step 1 of 2: choose a shared folder"),
        "body": [_section(COLOR_PENDING, items)],
    }


def _text_input(action_id: str, label: str, placeholder: str, multiline: bool = False,
                max_length: int = 500, value: str = "") -> Dict[str, Any]:
    return {"type": "plain_text_input", "action_id": action_id, "text": label, "value": value,
            "placeholder": placeholder, "multiline": multiline, "min_length": 0, "max_length": max_length}


def _path_parts(path: str, root: str = "") -> List[str]:
    """Subfolder path segments below ``root`` (the shared folder's own name is dropped if present)."""
    parts = [part.strip() for part in (path or "").split("/") if part.strip()]
    if len(parts) > 1 and root and parts[0] == root.strip():
        parts = parts[1:]
    return parts


def _subfolder_path(path: str, root: str) -> str:
    """One-line path from the shared folder down, e.g. ``"new prod / Demo Prod Cred's / POD 1"``."""
    parts = [part.replace("[Nested Share Folder]", "").replace("[nested share folder]", "").strip()
             for part in (_path_parts(path, root) or [path])]
    return " / ".join([root.strip()] + parts)


def build_create_secret_form(folder_uid: str, folder_name: str, is_nsf: bool,
                             subfolders: List[Dict[str, Any]], find: str = "",
                             prefill: Optional[Dict[str, str]] = None, notice: Optional[str] = None,
                             selected_uid: Optional[str] = None) -> Dict[str, Any]:
    """
    Step 2: target folder, then the record fields. ``find`` narrows the subfolder
    dropdown (Zoom dropdowns can't be searched); ``prefill`` keeps what the user had
    typed (never the password) when the form is redrawn; ``notice`` shows a warning (e.g.
    a missing title) and ``selected_uid`` keeps the chosen subfolder.
    """
    prefill = prefill or {}
    find = find.strip()
    items: List[Dict[str, Any]] = [
        _message(f"*Creating record in:* {folder_name} "
                 f"({'Nested Share Folder' if is_nsf else 'Shared Folder'})"),
    ]
    ordered = sorted(((sf, _subfolder_path(sf["path"], folder_name)) for sf in subfolders
                      if sf["uid"] != folder_uid), key=lambda pair: pair[1].lower())
    if ordered:
        # Zoom dropdowns can't be searched by typing, so the Find box is always offered
        items += [
            _text_input("cs_find", "Find folder", "Part of a folder name", value=find, max_length=100),
            {"type": "actions", "items": [
                {"text": "Find", "value": encode_folder(CS_FIND, folder_uid, is_nsf, folder_name),
                 "style": "Primary", "submit": True},
                {"text": "Re-Sync Vault", "value": encode_folder(CS_SUB_SYNC, folder_uid, is_nsf, folder_name),
                 "style": "Default", "submit": True},
            ]},
        ]
        matches = [(sf, label) for sf, label in ordered if find.lower() in label.lower()]
        badge = _folder_badge(is_nsf)  # subfolders have their shared folder's type
        options = [(encode_folder(CS_SUBFOLDER, folder_uid, is_nsf), f"{badge} {truncate_text(folder_name, 60)} (top level)")]
        # The value keeps the path below the shared folder; the result card prefixes the folder name
        options += [(encode_folder(CS_SUBFOLDER, sf["uid"], is_nsf or sf["is_nsf"],
                                   truncate_text(" / ".join(_path_parts(sf["path"], folder_name)), 80)),
                     f"{badge} {truncate_text(label, 90)}")
                    for sf, label in matches]
        select_items = [{"text": label, "value": value} for value, label in options[:MAX_SEARCH_RESULTS + 1]]
        items.append({"type": "select", "text": "Save in (optional subfolder)", "select_items": select_items,
                      "selected_item": dict(next(
                          (item for item in select_items if selected_uid and f"|{selected_uid}|" in item["value"]),
                          select_items[0]))})  # the shared folder itself unless one was chosen
        shown = len(select_items) - 1
        if find and not matches:
            items.append(_note(f"No subfolders match \"{find}\". The record will go in the top level "
                               f"unless you search again.", NOTE_WARN))
        elif find:
            items.append(_note(f"{len(matches)} subfolder(s) match \"{find}\""
                               + (f"; showing the first {shown}." if shown < len(matches) else ".")))
        elif shown < len(ordered):
            items.append(_note(f"Showing the first {shown} of {len(ordered)} subfolders. "
                               f"Use Find folder to reach the rest."))
    items += [
        _text_input("cs_title", "Title (required)", "Record title", value=prefill.get("title", "")),
        _text_input("cs_login", "Login", "Email or username", value=prefill.get("login", "")),
        _text_input("cs_password", "Password", PASSWORD_PLACEHOLDER),
        _note(PASSWORD_HINT),
        _text_input("cs_url", "Website Address", "https://", value=prefill.get("url", "")),
        _text_input("cs_notes", "Notes", "Optional notes", multiline=True, max_length=2000,
                    value=prefill.get("notes", "")),
    ]
    if notice:
        items.append(_input_warning(notice))
    items.append({"type": "actions", "items": [
        {"text": "Create Record", "value": encode_folder(CS_CREATE, folder_uid, is_nsf, folder_name),
         "style": "Primary", "submit": True},
        {"text": "Back", "value": encode_value(CS_BACK, ""), "style": "Default"},
        {"text": "Cancel", "value": encode_value(CS_CANCEL, ""), "style": "Danger"},
    ]})
    return {
        "settings": {"form": True},
        "head": _head(CREATE_SECRET_TITLE, "Step 2 of 2: record details"),
        "body": [_section(COLOR_PENDING, items)],
    }


def build_create_secret_result(title: str, record_uid: str, folder_path: str,
                               error: Optional[str] = None) -> Dict[str, Any]:
    if error:
        return {
            "head": _head(CREATE_SECRET_TITLE, "Failed"),
            "body": [_section(COLOR_DENIED, [
                _message("*Failed to Create Record*"),
                _note(f"Could not create {sanitize_hyperlinks(title)}: {error}", NOTE_ERROR),
                _message("Run `/keeper create-secret` to try again, or contact your administrator."),
            ])],
        }
    return {
        "head": _head(CREATE_SECRET_TITLE, "Record created"),
        "body": [_section(COLOR_APPROVED, [
            _note("Record Created Successfully!", NOTE_SUCCESS),
            _fields([("Title", sanitize_hyperlinks(title)), ("Record UID", record_uid),
                     ("Folder", folder_path)], wide=("Folder",)),
            _message("The record has been created in the Keeper vault."),
        ])],
    }


def build_create_secret_notification(user_name: str, record_uid: str, title: str, folder_path: str) -> Dict[str, Any]:
    """Approvals-channel notice for a created secret. No secrets included."""
    return {
        "head": _head("New Secret Record Created"),
        "body": [_section(COLOR_NEUTRAL, [_fields([
            ("User", user_name), ("Record UID", record_uid),
            ("Title", sanitize_hyperlinks(title)), ("Folder", folder_path),
        ])], footer=f"Created via /keeper create-secret • {now_display()}")],
    }


def build_usage_content(error: Optional[str] = None, level: str = "WARN") -> Dict[str, Any]:
    text = (
        "*Commands*\n"
        "• `/keeper request-record \"Record UID or description\" Justification`\n"
        "• `/keeper request-folder \"Folder UID or description\" Justification`\n"
        "• `/keeper one-time-share \"Record UID or description\" Justification`\n"
        "• `/keeper create-secret`\n"
        "• `/keeper help`\n\n"
        "Examples:\n"
        "• `/keeper request-record kR3a1bCdEfGhIjKlMnOpQr Need to run DB migration (JIRA-123)`\n"
        "• `/keeper request-folder \"Staging credentials\" Deploying release 4.2 (JIRA-456)`"
    )
    if error:
        return {"head": _head(APP_NAME), "body": [_note(error.replace("*", ""), level), _message(text)]}
    return text_content(text)
