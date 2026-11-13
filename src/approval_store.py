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
Persistent store for approval requests.

Slack sends the full request back in the button ``value`` and the approver's
dropdown choices in ``state``. Zoom sends only the clicked button's value, so
each request (and the approver's current selections) is kept here, keyed by
approval ID, and written to a JSON file so pending cards survive restarts.
"""

import json
import os
import threading
import time
from contextlib import contextmanager
from typing import Dict, Iterator, Optional

from .logger import logger
from .models import AccessRequest, RequestStatus


# Resolved requests are dropped after this many days
RETENTION_SECONDS = 30 * 24 * 3600


class ApprovalStore:
    """Thread-safe, file-backed map of approval_id -> AccessRequest."""

    def __init__(self, data_dir: str, filename: str = "approvals.json"):
        os.makedirs(data_dir, exist_ok=True)
        self.path = os.path.join(data_dir, filename)
        self._lock = threading.RLock()
        self._item_locks: Dict[str, threading.Lock] = {}
        self._items: Dict[str, Dict] = {}
        self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r") as f:
                self._items = json.load(f) or {}
            logger.info(f"Loaded {len(self._items)} approval request(s) from {self.path}")
        except Exception as e:
            logger.error(f"Could not load approval store {self.path}: {e}")
            self._items = {}

    def _flush(self):
        now = time.time()
        self._items = {
            k: v for k, v in self._items.items()
            if v.get("status") not in RequestStatus.FINAL
            or now - v.get("_updated", now) < RETENTION_SECONDS
        }
        tmp_path = self.path + ".tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self._items, f, indent=2)
        os.replace(tmp_path, self.path)

    def save(self, request: AccessRequest):
        with self._lock:
            data = request.to_dict()
            data["_updated"] = time.time()
            self._items[request.approval_id] = data
            self._flush()

    def get(self, approval_id: str) -> Optional[AccessRequest]:
        with self._lock:
            data = self._items.get(approval_id)
            return AccessRequest.from_dict(data) if data else None

    @contextmanager
    def locked(self, approval_id: str) -> Iterator[Optional[AccessRequest]]:
        """
        Serialize work on one approval (e.g. two approvers clicking at once).
        Yields the current request (or None). Callers must ``save()`` changes.
        """
        with self._lock:
            item_lock = self._item_locks.setdefault(approval_id, threading.Lock())
        with item_lock:
            yield self.get(approval_id)
