"""KeeperClient command construction, against a fake Commander Service Mode."""

import pytest

from src.config import KeeperConfig
from src.keeper_client import KeeperClient
from src.models import NSFPermissionRole, PermissionLevel


class FakeResponse:
    def __init__(self, status, data):
        self.status_code = status
        self._data = data
        self.text = str(data)

    def json(self):
        return self._data


class FakeCommander:
    """Records submitted commands; returns canned results by command prefix."""

    def __init__(self, results=None, submit_status=202):
        self.commands = []
        self.results = results or {}
        self.submit_status = submit_status
        self.headers = {}

    def post(self, url, json=None, timeout=None):
        self.commands.append(json["command"])
        return FakeResponse(self.submit_status, {"request_id": str(len(self.commands) - 1)})

    def get(self, url, timeout=None):
        cmd = self.commands[int(url.rsplit("/", 1)[1])]
        for prefix, result in self.results.items():
            if cmd.startswith(prefix):
                return FakeResponse(200, result)
        return FakeResponse(200, {"status": "success", "message": []})


@pytest.fixture
def make_client():
    def _make(**kwargs):
        client = KeeperClient(KeeperConfig(service_url="http://x/api/v2", api_key="k"), fetch_server_domain=False)
        client.session = FakeCommander(**kwargs)
        return client
    return _make


UID = "AbCdEfGhIjKlMnOpQrStUv"


def test_grant_can_edit_with_expiry(make_client):
    kc = make_client()
    result = kc.grant_record_access(UID, "a@b.com", PermissionLevel.CAN_EDIT, duration_seconds=3600)
    assert result["success"]
    cmds = kc.session.commands
    assert cmds[0] == "sync-down"
    assert cmds[1].startswith("get --format=json")
    assert cmds[2] == f"share-record {UID} -e a@b.com -a revoke --force"
    assert cmds[3] == f"share-record {UID} -e a@b.com -a grant -w --expire-in 1h --force"


def test_grant_pam_rotate(make_client):
    kc = make_client()
    kc.grant_record_access(UID, "a@b.com", PermissionLevel.VIEW_ONLY, duration_seconds=300, rotate_on_expire=True)
    assert kc.session.commands[-1].endswith("--expire-in 5mi --rotate-on-expiration --force")


def test_grant_permanent_only_has_no_expiry(make_client):
    kc = make_client()
    kc.grant_record_access(UID, "a@b.com", PermissionLevel.EDIT_AND_SHARE, duration_seconds=3600)
    assert kc.session.commands[-1] == f"share-record {UID} -e a@b.com -a grant -w -s --force"


def test_grant_to_owner_is_refused(make_client):
    kc = make_client(results={"get ": {"status": "success", "data": {
        "user_permissions": [{"username": "A@b.com", "owner": True}]}}})
    result = kc.grant_record_access(UID, "a@b.com", PermissionLevel.VIEW_ONLY)
    assert not result["success"] and "record owner" in result["error"]
    assert not any(c.startswith("share-record") for c in kc.session.commands)


def test_invitation_detected(make_client):
    kc = make_client(results={"share-record " + UID + " -e a@b.com -a grant": {
        "status": "success", "message": ["Share invitation has been sent to a@b.com"]}})
    result = kc.grant_record_access(UID, "a@b.com", PermissionLevel.VIEW_ONLY, duration_seconds=300)
    assert result["invitation_sent"]


def test_rotation_not_configured(make_client):
    kc = make_client(results={"share-record " + UID + " -e a@b.com -a grant": {
        "status": "error", "message": "Rotation must be already set on the record"}})
    result = kc.grant_record_access(UID, "a@b.com", PermissionLevel.VIEW_ONLY, 300, rotate_on_expire=True)
    assert result["error_code"] == "pam_rotation_not_configured"


def test_command_not_allowed(make_client):
    kc = make_client(submit_status=403)
    result = kc.grant_record_access(UID, "a@b.com", PermissionLevel.VIEW_ONLY)
    assert result["error_code"] == "command_not_allowed"


def test_nsf_grant(make_client):
    kc = make_client()
    kc.grant_nsf_record_access(UID, "a@b.com", NSFPermissionRole.FULL_MANAGER, duration_seconds=86400)
    assert kc.session.commands[-1] == f"nsf-share-record {UID} -e a@b.com -a grant -r full-manager --expire-in 1d -f"


def test_get_record_by_uid_picks_exact_match(make_client):
    kc = make_client(results={"search ": {"status": "success", "data": [
        {"uid": "OTHERuidOTHERuidOTHER1", "name": "Nope", "type": "record", "details": "Type: login"},
        {"uid": UID, "name": "Prod DB", "type": "record",
         "details": "Type: pamUser, Description: root, Record Category: Nested"},
    ]}})
    rec = kc.get_record_by_uid(UID)
    assert (rec.title, rec.record_type, rec.notes, rec.is_nsf) == ("Prod DB", "pamUser", "root", True)


def test_search_sanitizes_query(make_client):
    kc = make_client(results={"search -c r": {"status": "success", "data": []}})
    kc.search_records('prod"; rm -rf /')
    assert kc.session.commands[-1] == 'search -c r "prod rm -rf /" --format=json'
