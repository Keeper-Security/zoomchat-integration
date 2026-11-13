"""Shared fixtures: a KeeperZoomApp wired to fake Zoom and Commander backends."""

import hashlib
import hmac
import json
import os
import sys
import time

import pytest
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.app import KeeperZoomApp  # noqa: E402
from src.approval_store import ApprovalStore  # noqa: E402
from src.config import Config  # noqa: E402
from src.models import KeeperFolder, KeeperRecord  # noqa: E402

SECRET = "test-secret-token"
CHANNEL = "approvers123@conference.xmpp.zoom.us"
REQUESTER = {"userId": "req-1", "userJid": "req-1@xmpp.zoom.us", "userName": "Riley Requester"}
APPROVER = {"userId": "app-1", "userJid": "app-1@xmpp.zoom.us", "userName": "Avery Approver"}

UID = "AbCdEfGhIjKlMnOpQrStUv"
NSF_UID = "NsFrEcOrDuId0123456789"
PAM_UID = "PaMuSeRrEcOrD012345678"
FOLDER_UID = "FoLdErUiD0123456789abc"
NSF_FOLDER_UID = "NsFfOlDeRuId0123456789"
PAM_FOLDER_UID = "PaMfOlDeRuId0123456789"


class FakeZoomClient:
    def __init__(self):
        self.sent = []      # (to_jid, content, private_to_user_jid)
        self.edits = []     # (message_id, content)
        self.dms = []       # (user_jid, content)
        self.emails = {"req-1": "riley@example.com", "app-1": "avery@example.com"}
        self._n = 0

    def send_message(self, to_jid, content, user_jid, account_id=None):
        self._n += 1
        self.sent.append((to_jid, content, None))
        return f"msg-{self._n}"

    def edit_message(self, message_id, to_jid, content, user_jid, account_id=None):
        self.edits.append((message_id, content))

    def send_dm(self, user_jid, content, account_id=None):
        self.dms.append((user_jid, content))
        return True

    def send_ephemeral(self, user_jid, content, account_id=None):
        self.sent.append((user_jid, content, user_jid))
        return True

    def get_user_email(self, user_id, hint=None):
        return hint or self.emails.get(user_id)

    def has_user_token(self):
        return True

    # helpers
    def ephemerals_for(self, user_jid):
        return [c for _, c, vis in self.sent if vis == user_jid]

    def last_card(self):
        return self.edits[-1][1] if self.edits else None


class FakeKeeperClient:
    server_domain = "keepersecurity.com"

    def __init__(self):
        self.records = {
            UID: KeeperRecord(uid=UID, title="Prod DB", record_type="login", notes="db admin"),
            NSF_UID: KeeperRecord(uid=NSF_UID, title="NSF Secret", record_type="login", is_nsf=True),
            PAM_UID: KeeperRecord(uid=PAM_UID, title="PAM root", record_type="pamUser"),
        }
        self.folders = {
            FOLDER_UID: KeeperFolder(uid=FOLDER_UID, name="Staging creds"),
            NSF_FOLDER_UID: KeeperFolder(uid=NSF_FOLDER_UID, name="NSF Team",
                                         folder_type="nested_share_folder", is_nsf=True),
            PAM_FOLDER_UID: KeeperFolder(uid=PAM_FOLDER_UID, name="PAM users"),
        }
        self.pam_folders = {PAM_FOLDER_UID}
        self.grants = []
        self.nsf_grants = []
        self.folder_grants = []
        self.nsf_folder_grants = []
        self.syncs = 0
        self.grant_result = {"success": True, "expires_at": "2026-10-30 12:00 UTC"}

    def health_check(self):
        return True

    def get_record_by_uid(self, uid):
        if uid in self.folders:
            return KeeperRecord(uid=uid, title=self.folders[uid].name, record_type="shared_folder")
        return self.records.get(uid)

    def sync_down(self):
        self.syncs += 1
        return True, None

    def search_records(self, query, limit=20):
        return [r for r in self.records.values() if query.lower() in r.title.lower()], None

    def get_folder_by_uid(self, uid):
        if uid in self.records:
            return KeeperFolder(uid=uid, name=self.records[uid].title, folder_type="record")
        folder = self.folders.get(uid)
        return KeeperFolder.from_dict(folder.to_dict()) if folder else None

    def search_folders(self, query, limit=20):
        return [KeeperFolder.from_dict(f.to_dict()) for f in self.folders.values()
                if query.lower() in f.name.lower()], None

    def is_pam_user_folder(self, uid):
        return uid in self.pam_folders, None

    def grant_folder_access(self, folder_uid, user_email, permission, duration_seconds=None, rotate_on_expire=False):
        self.folder_grants.append(dict(uid=folder_uid, email=user_email, permission=permission,
                                       duration=duration_seconds, rotate=rotate_on_expire))
        return dict(self.grant_result)

    def grant_nsf_folder_access(self, folder_uid, user_email, role, duration_seconds=None):
        self.nsf_folder_grants.append(dict(uid=folder_uid, email=user_email, role=role, duration=duration_seconds))
        return dict(self.grant_result)

    def get_user_teams(self, email):
        return []

    def grant_record_access(self, record_uid, user_email, permission, duration_seconds=None, rotate_on_expire=False):
        self.grants.append(dict(uid=record_uid, email=user_email, permission=permission,
                                duration=duration_seconds, rotate=rotate_on_expire))
        return dict(self.grant_result)

    def grant_nsf_record_access(self, record_uid, user_email, role, duration_seconds=None):
        self.nsf_grants.append(dict(uid=record_uid, email=user_email, role=role, duration=duration_seconds))
        return dict(self.grant_result)


@pytest.fixture
def env(tmp_path):
    cfg = {
        "zoom": {
            "client_id": "cid", "client_secret": "csecret",
            "bot_jid": "bot@xmpp.zoom.us", "secret_token": SECRET,
            "approvals_channel_jid": CHANNEL,
        },
        "keeper": {"service_url": "http://localhost:8900/api/v2", "api_key": "k"},
        "storage": {"data_dir": str(tmp_path / "data")},
    }
    path = tmp_path / "zoom_config.yaml"
    path.write_text(yaml.safe_dump(cfg))

    config = Config(str(path))
    zoom = FakeZoomClient()
    keeper = FakeKeeperClient()
    store = ApprovalStore(config.data_dir)
    app = KeeperZoomApp(config=config, keeper_client=keeper, zoom_client=zoom, store=store, run_async=False)
    client = app.flask_app.test_client()

    def post(event, secret=SECRET):
        body = json.dumps(event).encode()
        ts = str(int(time.time()))
        sig = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
        return client.post("/zoom/webhook", data=body, headers={
            "x-zm-request-timestamp": ts, "x-zm-signature": sig, "Content-Type": "application/json",
        })

    class Env:
        pass

    e = Env()
    e.app, e.zoom, e.keeper, e.store, e.client, e.post = app, zoom, keeper, store, client, post
    return e


def slash(cmd, user=REQUESTER, to_jid=CHANNEL):
    return {"event": "bot_notification", "payload": {"accountId": "acct-1", "cmd": cmd, "toJid": to_jid, **user}}


def click(value, user=APPROVER):
    return {"event": "interactive_message_actions",
            "payload": {"accountId": "acct-1", "toJid": CHANNEL, "messageId": "msg-1",
                        "actionItem": {"text": "x", "value": value}, **user}}


def choose(value, user=APPROVER):
    return {"event": "interactive_message_select",
            "payload": {"accountId": "acct-1", "toJid": CHANNEL, "messageId": "msg-1",
                        "selectedItems": [{"text": "x", "value": value}], **user}}


def submit(choice, button, user=APPROVER):
    """``chat_message.submit`` from a form card (radio choice + submit button)."""
    items = [{"actionItem": {"text": "Use Selected Record", "value": button}}]
    if choice:
        items.append({"radio_buttons": {"value": choice, "action_id": choice.rsplit("|", 1)[0]}})
    return {"event": "chat_message.submit",
            "payload": {"account_id": "acct-1", "operator_id": user["userId"],
                        "object": {"to_jid": CHANNEL, "user_jid": user["userJid"], "submit_items": items}}}


def card_values(content):
    """All interactive values in a card (buttons + select items)."""
    values = []
    items = list(content["body"])
    for item in items:
        if item["type"] == "section":
            items += item["sections"]
        if item["type"] == "actions":
            values += [b["value"] for b in item["items"]]
        if item["type"] == "select":
            values += [s["value"] for s in item["select_items"]]
        if item["type"] == "radio_buttons":
            values += [o["value"] for o in item["options"]]
    return values


def card_text(content):
    return json.dumps(content)
