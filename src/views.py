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
Zoom chatbot message cards (the Zoom equivalent of the Slack Block Kit views).

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
    """Minimum access by default (Slack: View Only / No User Permissions / NSF Viewer)."""
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


def select_item(request: AccessRequest, item: Item):
    """Make ``item`` the record/folder being approved and reset choices to safe defaults."""
    request.selected = item.to_dict()
    request.permission = default_permission(item)
    if request.duration == "permanent" and is_pam_target(item):
        request.duration = "5m"
    request.banner = None


# ----------------------------------------------------------------------
# Approval card
# ----------------------------------------------------------------------

def _noun(request: AccessRequest) -> str:
    return request.item_noun.capitalize()


def _card_title(request: AccessRequest) -> str:
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
    badge = "📂 NSF" if item.get("is_nsf") else "🔑 Classic"
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
    return _section(COLOR_PENDING, [
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
        {"type": "actions", "items": [
            {"text": f"Use Selected {_noun(request)}", "value": encode_value(ACTION_PICK, aid), "style": "Primary",
             "submit": True},
            {"text": "Search Again", "value": encode_value(ACTION_SEARCH, aid), "style": "Default"},
            {"text": "Deny", "value": encode_value(ACTION_DENY, aid), "style": "Danger"},
        ]},
    ])


def _pending_card(request: AccessRequest) -> Dict[str, Any]:
    aid = request.approval_id
    record = request.selected_item
    noun = request.item_noun
    card: Dict[str, Any] = {"head": _head(_card_title(request), f"from {request.requester_name}")}
    body: List[Dict[str, Any]] = [_section(COLOR_PENDING, [_request_fields(request)]), DIVIDER]
    card["body"] = body
    deny = ("Deny", encode_value(ACTION_DENY, aid), "Danger")

    # Description request: approver must search and pick the record/folder first
    if not request.is_uid and not record:
        if not request.searched:
            body.append(_section(COLOR_PENDING, [
                _message(f"*Action Required:* search the vault for the requested {noun}."),
                _buttons([(f"Search {_noun(request)}s", encode_value(ACTION_SEARCH, aid), "Primary"), deny]),
            ]))
            return card

        if not request.search_results:
            items = [_message(
                f"No {noun}s found matching *{sanitize_hyperlinks(request.identifier)}*. "
                f"Ask the requester for the {noun} UID, or deny the request."
            )]
            if request.banner:
                items.append(_message(f"⚠️ {request.banner}"))
            items.append(_buttons([("Search Again", encode_value(ACTION_SEARCH, aid), "Default"), deny]))
            body.append(_section(COLOR_PROCESSING, items))
            return card

        card["settings"] = {"form": True}
        body.append(_search_results_section(request))
        if request.banner:
            body.append(_section(COLOR_PROCESSING, [_message(f"⚠️ {request.banner}")]))
        return card

    controls: List[Dict[str, Any]] = []
    if record:
        body.append(_section(COLOR_PENDING, _item_details(record)))
        body.append(DIVIDER)

        label = "Permission Level (Nested Share Folder)" if record.is_nsf else "Permission Level"
        controls.append(_select(label, permission_options(record), SELECT_PERMISSION, aid, request.permission))
        if is_permanent_only(record, request.permission):
            controls.append(_message(
                f"ℹ️ _{format_permission_name(request.permission)} is always permanent (no time limit)._"
            ))
        else:
            pam = is_pam_target(record)
            controls.append(_select(
                "Grant Access For", get_duration_options(exclude_permanent=pam),
                SELECT_DURATION, aid, request.duration,
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


def build_searching_card(request: AccessRequest) -> Dict[str, Any]:
    """Approval card while the vault is synced and searched (controls hidden)."""
    return {
        "head": _head(_card_title(request), f"from {request.requester_name}"),
        "body": [
            _section(COLOR_PENDING, [_request_fields(request)]),
            DIVIDER,
            _section(COLOR_PROCESSING, [_message("⏳ *Syncing the vault and searching...*")]),
        ],
    }


def _status_section(color: str, title: str, lines: List[str], footer: str) -> Dict[str, Any]:
    text = f"*{title}*" + "".join(f"\n{line}" for line in lines)
    return _section(color, [_message(text)], footer=footer)


def build_approval_card(request: AccessRequest) -> Dict[str, Any]:
    """Render the approvals-channel card for the request's current status."""
    status = request.status
    record = request.selected_item
    title = _card_title(request)
    sub_head = f"from {request.requester_name}"

    if status == RequestStatus.PENDING:
        return _pending_card(request)

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
            COLOR_PROCESSING, "⏳ Granting access...",
            [f"Approved by {request.approver_name}. This may take a few seconds."],
            footer="Keeper Security",
        ))
        return {"head": _head(title, "Granting access..."), "body": body}

    if status == RequestStatus.APPROVED:
        if request.duration == "permanent" or (record and is_permanent_only(record, request.permission)):
            lines = ["Access remains active indefinitely"]
            heading = "✅ Access Granted (No Expiration)"
        else:
            lines = [f"Access will expire on *{request.expires_at}*"]
            heading = "✅ Temporary Access Granted"
        lines.append(f"*Permission:* {format_permission_name(request.permission or '')}")
        if request.rotate_scheduled:
            lines.append("*PAM credentials will rotate* when access expires")
        body.append(_status_section(
            COLOR_APPROVED, heading, lines,
            footer=f"Approved by {request.approver_name} • {request.resolved_at}",
        ))
        return {"head": _head(f"{title} Approved", sub_head), "body": body}

    if status == RequestStatus.INVITATION_SENT:
        body.append(_status_section(
            COLOR_APPROVED, "📨 Share Invitation Sent",
            ["A share invitation has been sent to the requester's email.",
             f"They must accept it and create a Keeper account to access this {request.item_noun}.",
             f"*Permission:* {format_permission_name(request.permission or '')}"],
            footer=f"Approved by {request.approver_name} • {request.resolved_at}",
        ))
        return {"head": _head(title, sub_head), "body": body}

    # DENIED / OWNER / FAILED
    icon = "🚫" if status == RequestStatus.DENIED else "⚠️"
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


def update_approval_card(zoom_client, request: AccessRequest) -> None:
    """Re-render the approval card in place."""
    if not request.message_id:
        logger.warning(f"No message_id for {request.approval_id}; cannot update card")
        return
    zoom_client.edit_message(
        message_id=request.message_id,
        to_jid=request.channel_jid,
        content=build_approval_card(request),
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
        ],
    }


def build_access_denied_content(request: AccessRequest) -> Dict[str, Any]:
    return text_content(
        f"*Access Request Denied*\n\n"
        f"Request ID: `{request.approval_id}`\n"
        f"{_noun(request)} access request was denied by {request.approver_name}.\n\n"
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


def build_usage_content(error: Optional[str] = None) -> Dict[str, Any]:
    text = (
        "*Commands*\n"
        "• `/keeper request-record \"Record UID or description\" Justification`\n"
        "• `/keeper request-folder \"Folder UID or description\" Justification`\n"
        "• `/keeper help`\n\n"
        "Examples:\n"
        "• `/keeper request-record kR3a1bCdEfGhIjKlMnOpQr Need to run DB migration (JIRA-123)`\n"
        "• `/keeper request-folder \"Staging credentials\" Deploying release 4.2 (JIRA-456)`"
    )
    if error:
        text = f"{error}\n\n{text}"
    return text_content(text)
