"""ZoomClient user email lookup order."""

import json
import time

from src.config import ZoomConfig
from src.zoom_client import ZoomClient


class FakeResponse:
    def __init__(self, status, data):
        self.status_code = status
        self._data = data
        self.text = json.dumps(data)

    def json(self):
        return self._data


class FakeSession:
    def __init__(self, users=None, me=None):
        self.users = users or {}   # user_id -> email (200), else 401
        self.me = me               # /users/me body, or None for 401
        self.calls = []

    def post(self, url, params=None, headers=None, timeout=None):
        return FakeResponse(200, {"access_token": "bot", "expires_in": 3600})

    def get(self, url, headers=None, timeout=None):
        path = url.split("/v2", 1)[1]
        self.calls.append(path)
        if path == "/users/me":
            return FakeResponse(200, self.me) if self.me else FakeResponse(401, {"code": 124})
        uid = path.rsplit("/", 1)[1]
        if uid in self.users:
            return FakeResponse(200, {"email": self.users[uid]})
        return FakeResponse(401, {"code": 124, "message": "Invalid access token."})


def make(tmp_path, session, user_emails=None, with_user_token=True):
    cfg = ZoomConfig("cid", "secret", "bot@xmpp.zoom.us", "tok",
                     "c@conference.xmpp.zoom.us", user_emails=user_emails or {})
    zc = ZoomClient(cfg, str(tmp_path))
    zc.session = session
    if with_user_token:
        with open(zc._user_token_path, "w") as f:
            json.dump({"access_token": "user", "expires_at": time.time() + 3600}, f)
    return zc


def test_payload_hint_wins(tmp_path):
    zc = make(tmp_path, FakeSession())
    assert zc.get_user_email("u1", hint="a@b.com") == "a@b.com"


def test_config_mapping_by_id_or_jid(tmp_path):
    zc = make(tmp_path, FakeSession(), user_emails={"B_ABC@xmpp.zoom.us": "abc@x.com"})
    assert zc.get_user_email("b_abc") == "abc@x.com"


def test_admin_scope_lookup(tmp_path):
    zc = make(tmp_path, FakeSession(users={"u1": "u1@x.com"}))
    assert zc.get_user_email("u1") == "u1@x.com"


def test_users_me_for_user_managed_app(tmp_path):
    me = {"id": "VF51", "jid": "b_vf51@xmpp.zoom.us", "email": "me@x.com"}
    zc = make(tmp_path, FakeSession(me=me))
    assert zc.get_user_email("b_VF51") == "me@x.com"


def test_users_me_never_returns_other_users_email(tmp_path):
    me = {"id": "someone", "jid": "someone@xmpp.zoom.us", "email": "me@x.com"}
    zc = make(tmp_path, FakeSession(me=me))
    assert zc.get_user_email("b_other") is None
