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

MAX_LISTED_RESULTS = 10
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
    # Radio options are plain text, so the folder-type badge is an emoji marker
    badge = ":open_file_folder: NSF" if item.get("is_nsf") else ":key: Classic"
    title = sanitize_hyperlinks(truncate_text(item.get("title") or item.get("name") or "Untitled", 60))
    return f"{badge}  |  {title}  ·  {item.get('uid', '')}"


def _search_results_section(request: AccessRequest) -> Dict[str, Any]:
    """Radio list of results, submitted with one button (Zoom form card)."""
    aid = request.approval_id
    results = request.search_results[:MAX_LISTED_RESULTS]
    summary = (f"{len(results)} result(s) for `{sanitize_hyperlinks(request.identifier)}` "
               f"• searched {datetime.now().strftime('%H:%M:%S')}")
    if len(request.search_results) > len(results):
        summary += f" (first {len(results)} of {len(request.search_results)})"
    buttons = [
        {"text": f"Use Selected {_noun(request)}", "value": encode_value(ACTION_PICK, aid), "style": "Primary",
         "submit": True},
        {"text": "Search Again", "value": encode_value(ACTION_SEARCH, aid), "style": "Default"},
    ]
    if can_create_record(request):
        buttons.append({"text": "Create New Record", "value": encode_value(ACTION_NEW_RECORD, aid),
                        "style": "Primary"})
    buttons.append({"text": "Deny", "value": encode_value(ACTION_DENY, aid), "style": "Danger"})
    items = [
        {"type": "message", "text": f"Select a {request.item_noun}", "style": {"bold": True}},
        _message(f"_{summary}_"),
        {
            "type": "radio_buttons",
            "action_id": f"{SELECT_RECORD}|{aid}",
            "options": [
                {"text": _result_label(item), "value": encode_value(SELECT_RECORD, aid, str(idx))}
                for idx, item in enumerate(results)
            ],
        },
        {"type": "actions", "items": buttons},
    ]
    if can_create_record(request):
        items.append(_message("_Or create a new record and share it_"))
    return _section(COLOR_PENDING, items)


def _pending_card(request: AccessRequest, form_prefill: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
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
                items.append(_message(f":warning: *Search failed:* {request.banner}"))
            items.append(_buttons([(f"Search {_noun(request)}s", encode_value(ACTION_SEARCH, aid), "Primary"), deny]))
            body.append(_section(COLOR_PROCESSING if request.banner else COLOR_PENDING, items))
            return card

        if not request.search_results:
            items = [_message(
                f"No {noun}s found matching *{sanitize_hyperlinks(request.identifier)}*. "
                f"Ask the requester for the {noun} UID, or deny the request."
            )]
            if request.banner:
                items.append(_message(f":warning: {request.banner}"))
            buttons = [("Search Again", encode_value(ACTION_SEARCH, aid), "Default")]
            if can_create_record(request):
                buttons.append(("Create New Record", encode_value(ACTION_NEW_RECORD, aid), "Primary"))
            items.append(_buttons(buttons + [deny]))
            if can_create_record(request):
                items.append(_message("_Or create a new record and share it_"))
            body.append(_section(COLOR_PROCESSING, items))
            return card

        card["settings"] = {"form": True}
        body.append(_search_results_section(request))
        if request.banner:
            body.append(_section(COLOR_PROCESSING, [_message(f":warning: {request.banner}")]))
        return card

    controls: List[Dict[str, Any]] = []
    self_destruct = self_destruct_for(request, record)
    if record:
        body.append(_section(COLOR_PENDING, _item_details(record)))
        body.append(DIVIDER)

    if self_destruct:
        # The approver chose these when creating the record, so no selectors
        controls.append(_message(
            f"*Self-Destruct Record Settings*\n\nRecord will be shared directly to the requester's vault\n"
            f"Auto-deletes after: *{format_duration(self_destruct)}*\nAccess: View Only"
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
            controls.append(_message(
                f":information_source: _{format_permission_name(request.permission)} is always permanent (no time limit)._"
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
                controls.append(_message(
                    "_PAM User folder: credentials in this folder rotate when time-limited access expires "
                    "(rotation must be configured on the underlying records)._"
                    if request.is_folder else
                    "_PAM User record: credentials rotate when time-limited access expires "
                    "(rotation must be configured on the record)._"
                ))

    buttons = [("Approve", encode_value(ACTION_APPROVE, aid), "Primary"), deny]
    if not request.is_uid:
        buttons.append((f"Change {_noun(request)}", encode_value(ACTION_CHANGE_RECORD, aid), "Default"))
    controls.append(_buttons(buttons))
    body.append(_section(COLOR_PENDING, controls))

    if request.banner:
        body.append({"type": "alert", "text": f"Last attempt failed: {request.banner}", "level": "ERROR"})
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
        card["body"].append({"type": "alert", "text": f"Could not create record: {request.banner}",
                             "level": "ERROR"})
    card["body"].append(_section(COLOR_PENDING, [
        _message(f"*Create New Record* for {request.requester_name}\n"
                 f"You'll approve sharing once it's created."),
        _message("*1. Permission model*"),
        _buttons([(label, encode_value(ACTION_PERMISSION_MODEL, aid, value),
                   "Primary" if value == model else "Default")
                  for value, label in PERMISSION_MODEL_OPTIONS]),
        _message(f"_{model_hint} Pick this first: switching clears the fields below._"),
    ]))

    items: List[Dict[str, Any]] = [
        _message("*2. Record details*"),
        _text_input("nr_title", "Title (required)", "Record title",
                    value=prefill.get("title", truncate_text(request.identifier, 500))),
        _text_input("nr_login", "Login (required)", "Email or username", value=prefill.get("login", "")),
        _text_input("nr_password", "Password", PASSWORD_PLACEHOLDER),
        _message(PASSWORD_HINT),
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
            _message("_Deletes the record from the vault after this time. The requester gets View Only access._"),
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
                         text: str = ":hourglass_flowing_sand: *Syncing the vault and searching...*") -> Dict[str, Any]:
    """Approval card while Commander works (vault sync / search / record creation), controls hidden."""
    return {
        "head": _head(_card_title(request), f"from {request.requester_name}"),
        "body": [
            _section(COLOR_PENDING, [_request_fields(request)]),
            DIVIDER,
            _section(COLOR_PROCESSING, [_message(text)]),
        ],
    }


def _status_section(color: str, title: str, lines: List[str], footer: str) -> Dict[str, Any]:
    text = f"*{title}*" + "".join(f"\n{line}" for line in lines)
    return _section(color, [_message(text)], footer=footer)


def build_approval_card(request: AccessRequest, form_prefill: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Render the approvals-channel card for the request's current status.
    ``form_prefill`` re-fills the Create New Record form after a failed attempt.
    """
    status = request.status
    record = request.selected_item
    title = _card_title(request)
    sub_head = f"from {request.requester_name}"

    if status == RequestStatus.PENDING:
        return _pending_card(request, form_prefill)

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
            COLOR_PROCESSING, ":hourglass_flowing_sand: Granting access...",
            [f"Approved by {request.approver_name}. This may take a few seconds."],
            footer="Keeper Security",
        ))
        return {"head": _head(title, "Granting access..."), "body": body}

    if status == RequestStatus.APPROVED and request.is_one_time_share:
        body.append(_status_section(
            COLOR_APPROVED, ":link: One-Time Share Link Created",
            ["The link was sent to the requester by DM.",
             f"Link expires on *{request.expires_at}*",
             f"*Permission:* {format_permission_name(request.permission or '')}"],
            footer=f"Approved by {request.approver_name} • {request.resolved_at}",
        ))
        return {"head": _head("One-Time Share Request Approved", sub_head), "body": body}

    if status == RequestStatus.APPROVED:
        if request.duration == "permanent" or (record and is_permanent_only(record, request.permission)):
            lines = ["Access remains active indefinitely"]
            heading = ":white_check_mark: Access Granted (No Expiration)"
        else:
            lines = [f"Access will expire on *{request.expires_at}*"]
            heading = ":white_check_mark: Temporary Access Granted"
        lines.append(f"*Permission:* {format_permission_name(request.permission or '')}")
        if request.rotate_scheduled:
            lines.append("*PAM credentials will rotate* when access expires")
        self_destruct = self_destruct_for(request, record)
        if self_destruct:
            lines.append(f"\n*Self-Destruct Record*\nRecord will auto-delete after {format_duration(self_destruct)}")
        body.append(_status_section(
            COLOR_APPROVED, heading, lines,
            footer=f"Approved by {request.approver_name} • {request.resolved_at}",
        ))
        approved_title = "Self-Destruct Record Access Approved" if self_destruct else f"{title} Approved"
        return {"head": _head(approved_title, sub_head), "body": body}

    if status == RequestStatus.INVITATION_SENT:
        body.append(_status_section(
            COLOR_APPROVED, ":incoming_envelope: Share Invitation Sent",
            ["A share invitation has been sent to the requester's email.",
             f"They must accept it and create a Keeper account to access this {request.item_noun}.",
             f"*Permission:* {format_permission_name(request.permission or '')}"],
            footer=f"Approved by {request.approver_name} • {request.resolved_at}",
        ))
        return {"head": _head(title, sub_head), "body": body}

    # DENIED / OWNER / FAILED
    icon = ":no_entry_sign:" if status == RequestStatus.DENIED else ":warning:"
    body.append(_status_section(
        COLOR_DENIED, f"{icon} {request.status_text}", [], footer=f"Updated {request.resolved_at}",
    ))
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
                         form_prefill: Optional[Dict[str, str]] = None) -> None:
    """Re-render the approval card in place."""
    if not request.message_id:
        logger.warning(f"No message_id for {request.approval_id}; cannot update card")
        return
    zoom_client.edit_message(
        message_id=request.message_id,
        to_jid=request.channel_jid,
        content=build_approval_card(request, form_prefill),
        user_jid=request.requester_jid,
        account_id=request.account_id,
    )


def now_display() -> str:
    return datetime.now().strftime('%B %d, %Y at %I:%M %p')


# ----------------------------------------------------------------------
# Requester DMs
# ----------------------------------------------------------------------

def get_vault_deep_link(uid: str, server_domain: str = DEFAULT_KEEPER_DOMAIN, is_folder: bool = False) -> str:
    """Keeper vault deep link for a record or shared folder."""
    if is_folder:
        return f"https://{server_domain}/vault/#shared_folder/{uid}"
    return f"https://{server_domain}/vault/#detail/{uid}"


def build_request_submitted_content(request: AccessRequest) -> Dict[str, Any]:
    noun = _noun(request)
    if request.is_one_time_share:
        return text_content(
            f"*One-Time Share request submitted!*\n\n"
            f"Request ID: `{request.approval_id}`\n"
            f"Record: `{request.identifier}`\n"
            f"Justification: {request.justification}\n\n"
            f"Your request has been sent to the approvers channel.\n"
            f"Once approved, the one-time share link will be sent to you via DM.",
        )
    return text_content(
        f"*{noun} access request submitted!*\n\n"
        f"Request ID: `{request.approval_id}`\n"
        f"{noun}: `{request.identifier}`\n"
        f"Justification: {request.justification}\n\n"
        f"Your request has been sent to the approvers channel.\n"
        f"Once approved, the details will be sent to you via DM.",
    )


def build_access_granted_content(
    request: AccessRequest,
    server_domain: str = DEFAULT_KEEPER_DOMAIN,
) -> Dict[str, Any]:
    item = request.selected_item
    uid = item.uid if item else request.identifier
    title = item.title if item else uid
    return {
        "head": {"text": "Access Granted!"},
        "body": [
            _fields([
                ("Request ID", request.approval_id),
                (_noun(request), title),
                ("Permission", format_permission_name(request.permission or "")),
                ("Expires", request.expires_at or format_duration(request.duration)),
            ]),
            {"type": "message",
             "text": f"Open in Vault: {get_vault_deep_link(uid, server_domain, request.is_folder)}"},
        ] + ([_message(
            f"*Self-Destruct Record*\nThis record will automatically delete from the vault after "
            f"{format_duration(self_destruct_for(request, item))}."
        )] if self_destruct_for(request, item) else []),
    }


def build_share_link_content(request: AccessRequest, share_url: str) -> Dict[str, Any]:
    """DM with the one-time share link."""
    item = request.selected_item
    return {
        "head": {"text": "One-Time Share Link Created"},
        "body": [
            _fields([
                ("Request ID", request.approval_id),
                ("Record", item.title if item else request.identifier),
                ("Permission", format_permission_name(request.permission or "")),
                ("Expires", request.expires_at or format_duration(request.duration)),
            ]),
            _message(f"*Share Link:*\n{share_url}"),
            _message(
                "*Security Notice:*\n"
                "• This link can only be opened on ONE device\n"
                "• It expires after first access or when the time limit is reached\n"
                "• Share it only through secure channels\n"
                "• Do NOT post it in Zoom channels\n"
                "• Keep this link confidential"
            ),
        ],
    }


def build_access_denied_content(request: AccessRequest) -> Dict[str, Any]:
    return text_content(
        f"*Access Request Denied*\n\n"
        f"Request ID: `{request.approval_id}`\n"
        f"{'One-time share' if request.is_one_time_share else _noun(request) + ' access'} request was denied by "
        f"{request.approver_name}.\n\n"
        f"If you believe this was in error, please contact your manager or the security team.",
    )


def build_invitation_sent_content(request: AccessRequest) -> Dict[str, Any]:
    item = request.selected_item
    uid = item.uid if item else request.identifier
    noun = request.item_noun
    return text_content(
        f"*Share Invitation Sent*\n\n"
        f"Your request for {noun} `{uid}` has been approved!\n\n"
        f"However, you don't have a Keeper account yet. A share invitation has been sent to your email.\n\n"
        f"*Next Steps:*\n"
        f"1. Check your email for the Keeper invitation\n"
        f"2. Accept the invitation and create a Keeper account\n"
        f"3. The {noun} will be automatically shared with you\n\n"
        f"_Approved by {request.approver_name}_",
    )


# ----------------------------------------------------------------------
# Create secret (form cards in the user's 1:1 chat with the bot)
# ----------------------------------------------------------------------

CS_FOLDER = "csf"        # radio option: folder chosen
CS_NEXT = "csnext"       # submit: folder step
CS_SUBFOLDER = "cssub"   # dropdown option: target subfolder
CS_CREATE = "cscreate"   # submit: record form
CS_CANCEL = "cscancel"

CREATE_SECRET_TITLE = "Create Secret"
# Shared by the create-secret and Create New Record forms. Zoom draws inputs at a fixed
# width, so placeholders stay short enough to show in full.
PASSWORD_PLACEHOLDER = "Leave blank to auto-generate"
PASSWORD_HINT = "_:lock: Recommended: auto-generated passwords never pass through Zoom; typed ones do._"


def encode_folder(action: str, uid: str, is_nsf: bool, name: str = "") -> str:
    return encode_value(action, "", f"{uid}|{int(bool(is_nsf))}|{name}")


def decode_folder(value: str) -> Tuple[str, str, bool, str]:
    """``(action, uid, is_nsf, name)`` from :func:`encode_folder`."""
    action, _, arg = decode_value(value)
    uid, nsf, name = (arg.split("|", 2) + ["", "", ""])[:3]
    return action, uid, nsf == "1", name


def _folder_badge(is_nsf: bool) -> str:
    return ":open_file_folder: NSF" if is_nsf else ":key: Classic"


def build_create_secret_status(text: str) -> Dict[str, Any]:
    return text_content(text, title=CREATE_SECRET_TITLE)


def build_create_secret_folder_card(folders: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Step 1: pick one of the user's shared folders."""
    return {
        "settings": {"form": True},
        "head": _head(CREATE_SECRET_TITLE, "Step 1 of 2: choose a shared folder"),
        "body": [_section(COLOR_PENDING, [
            {"type": "message", "text": "Shared folders you can access", "style": {"bold": True}},
            {
                "type": "radio_buttons",
                "action_id": CS_FOLDER,
                "options": [
                    {"text": f"{_folder_badge(f['is_nsf'])}  |  {truncate_text(f['name'], 60)}",
                     "value": encode_folder(CS_FOLDER, f["uid"], f["is_nsf"], truncate_text(f["name"], 100))}
                    for f in folders
                ],
            },
            {"type": "actions", "items": [
                {"text": "Next", "value": encode_value(CS_NEXT, ""), "style": "Primary", "submit": True},
                {"text": "Cancel", "value": encode_value(CS_CANCEL, ""), "style": "Default"},
            ]},
        ])],
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


def _subfolder_label(path: str, root: str) -> str:
    """Indented tree entry, e.g. ``"  └ POD 1"`` for ``"Demo Prod Cred's/POD 1"``."""
    parts = _path_parts(path, root) or [path]
    name = parts[-1].replace("[Nested Share Folder]", "").replace("[nested share folder]", "").strip()
    return "\u2003" * (len(parts) - 1) + "└ " + truncate_text(name, 60)


def build_create_secret_form(folder_uid: str, folder_name: str, is_nsf: bool,
                             subfolders: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Step 2: target folder, then the record fields."""
    items: List[Dict[str, Any]] = [
        _message(f"*Creating record in:* {folder_name} "
                 f"({'Nested Share Folder' if is_nsf else 'Shared Folder'})"),
    ]
    if subfolders:
        # Tree order (each folder right after its parent), indented by depth
        ordered = sorted((sf for sf in subfolders if sf["uid"] != folder_uid),
                         key=lambda sf: [part.lower() for part in _path_parts(sf["path"], folder_name)])
        options = [(encode_folder(CS_SUBFOLDER, folder_uid, is_nsf), f":file_folder: {truncate_text(folder_name, 60)} (top level)")]
        options += [(encode_folder(CS_SUBFOLDER, sf["uid"], sf["is_nsf"],
                                   truncate_text(" / ".join(_path_parts(sf["path"], folder_name)), 80)),
                     _subfolder_label(sf["path"], folder_name))
                    for sf in ordered]
        select_items = [{"text": label, "value": value} for value, label in options]
        items.append({"type": "select", "text": "Save in (optional subfolder)", "select_items": select_items,
                      "selected_item": dict(select_items[0])})
    items += [
        _text_input("cs_title", "Title (required)", "Record title"),
        _text_input("cs_login", "Login", "Email or username"),
        _text_input("cs_password", "Password", PASSWORD_PLACEHOLDER),
        _message(PASSWORD_HINT),
        _text_input("cs_url", "Website Address", "https://"),
        _text_input("cs_notes", "Notes", "Optional notes", multiline=True, max_length=2000),
    ]
    items.append({"type": "actions", "items": [
        {"text": "Create Record", "value": encode_folder(CS_CREATE, folder_uid, is_nsf, folder_name),
         "style": "Primary", "submit": True},
        {"text": "Cancel", "value": encode_value(CS_CANCEL, ""), "style": "Default"},
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
            "body": [_section(COLOR_DENIED, [_message(
                f":x: *Failed to Create Record*\n\nCould not create *{sanitize_hyperlinks(title)}*:\n_{error}_\n\n"
                f"Run `/keeper create-secret` to try again, or contact your administrator."
            )])],
        }
    return {
        "head": _head(CREATE_SECRET_TITLE, "Record created"),
        "body": [_section(COLOR_APPROVED, [
            _message(":white_check_mark: *Record Created Successfully!*"),
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


def build_usage_content(error: Optional[str] = None) -> Dict[str, Any]:
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
        text = f"{error}\n\n{text}"
    return text_content(text)
