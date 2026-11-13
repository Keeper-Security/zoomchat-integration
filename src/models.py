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

"""Data models for Keeper Zoom Integration."""

from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Union


class RequestType(Enum):
    """Type of access request."""
    RECORD = "record"
    FOLDER = "folder"


class PermissionLevel(Enum):
    """Permission levels for Classic record and shared folder access."""

    # Record permissions
    VIEW_ONLY = "view_only"
    CAN_EDIT = "can_edit"
    CAN_SHARE = "can_share"
    EDIT_AND_SHARE = "edit_and_share"
    CHANGE_OWNER = "change_owner"

    # Shared folder permissions
    NO_PERMISSIONS = "no_permissions"
    MANAGE_USERS = "manage_users"
    MANAGE_RECORDS = "manage_records"
    MANAGE_ALL = "manage_all"


# Record permissions that are always permanent (no duration)
PERMANENT_ONLY_PERMISSIONS = (
    PermissionLevel.CAN_SHARE,
    PermissionLevel.EDIT_AND_SHARE,
    PermissionLevel.CHANGE_OWNER,
)

# Shared folder permissions that are always permanent (no duration)
FOLDER_PERMANENT_ONLY_PERMISSIONS = (
    PermissionLevel.MANAGE_USERS,
    PermissionLevel.MANAGE_ALL,
)


class NSFPermissionRole(Enum):
    """
    Role-based permissions for Nested Share Folder (NSF) records.
    """

    VIEWER = "viewer"
    SHARE_MANAGER = "share-manager"
    CONTENT_MANAGER = "content-manager"
    CONTENT_SHARE_MANAGER = "content-share-manager"
    FULL_MANAGER = "full-manager"
    TRANSFER_OWNER = "owner"


class RequestStatus:
    """Lifecycle states of an approval request."""
    PENDING = "pending"
    PROCESSING = "processing"
    APPROVED = "approved"
    DENIED = "denied"
    INVITATION_SENT = "invitation_sent"
    OWNER = "owner"
    FAILED = "failed"

    FINAL = (APPROVED, DENIED, INVITATION_SENT, OWNER, FAILED)


@dataclass
class KeeperRecord:
    """Represents a Keeper record."""

    uid: str
    """Unique identifier for the record"""

    title: str
    """Record title"""

    record_type: str
    """Type of record (e.g., 'login', 'pamUser')"""

    folder_uid: Optional[str] = None
    """UID of parent folder"""

    notes: Optional[str] = None
    """Record notes/description"""

    is_nsf: bool = False
    """
    True if this record is a Nested Share Folder (NSF) record (lives
    inside a nested share subfolder).
    """

    @property
    def display_name(self) -> str:
        """Get display name for UI."""
        return f"{self.title} ({self.uid[:8]}...)"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeeperRecord':
        return cls(
            uid=data.get('uid', ''),
            title=data.get('title', ''),
            record_type=data.get('record_type', 'login'),
            folder_uid=data.get('folder_uid'),
            notes=data.get('notes'),
            is_nsf=bool(data.get('is_nsf', False)),
        )


@dataclass
class KeeperFolder:
    """Represents a Keeper shared folder or Nested Share Folder."""

    uid: str
    name: str
    folder_type: str = "shared_folder"
    is_nsf: bool = False

    is_pam: bool = False
    """Classic shared folder whose PAM User records support rotate-on-expire"""

    @property
    def title(self) -> str:
        return self.name

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeeperFolder':
        return cls(
            uid=data.get('uid', ''),
            name=data.get('name') or data.get('title', ''),
            folder_type=data.get('folder_type', 'shared_folder'),
            is_nsf=bool(data.get('is_nsf', False)),
            is_pam=bool(data.get('is_pam', False)),
        )


@dataclass
class AccessRequest:
    """
    Represents a record or folder access request and the approver's current choices.

    Slack keeps the request in the button ``value`` and reads the approver's
    dropdown choices from the interaction ``state``. Zoom sends neither on a
    button click, so the full request lives here and is persisted by
    :class:`~src.approval_store.ApprovalStore`.
    """

    approval_id: str
    """Unique identifier for this approval request"""

    requester_id: str
    """Zoom user ID of requester"""

    requester_jid: str
    """Zoom user JID of requester (used to DM them)"""

    requester_name: str
    """Zoom display name of requester"""

    identifier: str
    """UID or description of the requested record or folder"""

    is_uid: bool
    """True if identifier is a UID, False if it's a description"""

    justification: str
    """Reason for requesting access"""

    created_at: str
    """When the request was created (display string)"""

    account_id: str = ""
    """Zoom account ID the request came from"""

    requester_email: Optional[str] = None
    """Requester email when Zoom included it in the event payload"""

    request_type: str = RequestType.RECORD.value

    channel_jid: str = ""
    """Approvals channel JID the card was posted to"""

    message_id: Optional[str] = None
    """Zoom message ID of the approval card"""

    status: str = RequestStatus.PENDING

    # Approver selections (Slack: card state)
    selected: Optional[Dict[str, Any]] = None
    """Item the approver is granting (KeeperRecord or KeeperFolder as dict)"""

    permission: Optional[str] = None
    """PermissionLevel or NSFPermissionRole value"""

    duration: str = "5m"
    """Duration of access (e.g., "5m", "1h", "24h", "7d", "permanent")"""

    rotate_on_expire: bool = True
    """PAM User records / folders only: rotate credentials when access expires"""

    # Description (non-UID) requests
    searched: bool = False
    search_results: List[Dict[str, Any]] = field(default_factory=list)

    banner: Optional[str] = None
    """Warning shown on the card (e.g., last approval attempt failed)"""

    # Resolution
    approver_name: Optional[str] = None
    resolved_at: Optional[str] = None
    status_text: Optional[str] = None
    expires_at: Optional[str] = None
    rotate_scheduled: bool = False

    @property
    def is_folder(self) -> bool:
        return self.request_type == RequestType.FOLDER.value

    @property
    def item_noun(self) -> str:
        """"record" or "folder", for card and message text."""
        return "folder" if self.is_folder else "record"

    def item_from_dict(self, data: Dict[str, Any]):
        return KeeperFolder.from_dict(data) if self.is_folder else KeeperRecord.from_dict(data)

    @property
    def selected_item(self) -> Optional[Union[KeeperRecord, KeeperFolder]]:
        return self.item_from_dict(self.selected) if self.selected else None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AccessRequest':
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})
