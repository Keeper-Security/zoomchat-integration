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
Keeper Service Mode API client.

Same Commander commands as the Slack app's record and folder flows:
``search``, ``get``, ``share-record``, ``nsf-share-record``, ``share-folder``,
``nsf-share-folder``, ``list-sf``, ``sync-down``, ``server`` and ``list-team``.
"""

import time
import requests
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta

from .models import (
    FOLDER_PERMANENT_ONLY_PERMISSIONS,
    KeeperFolder,
    KeeperRecord,
    PermissionLevel,
    NSFPermissionRole,
    PERMANENT_ONLY_PERMISSIONS,
)
from .config import KeeperConfig
from .logger import logger
from .utils import format_local_time
from .commander_errors import log_submit_warning, submit_error


class KeeperClient:
    """
    Interacting with Keeper Commander Service Mode API.
    """

    _FOLDER_ITEM_TYPES = frozenset({
        'shared_folder', 'nested_share_folder', 'user_folder', 'folder',
    })

    def __init__(self, config: KeeperConfig, fetch_server_domain: bool = True):
        self.base_url = config.service_url.rstrip('/')
        self.api_key = config.api_key

        # Session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})
        if self.api_key:
            self.session.headers.update({'api-key': self.api_key})

        self.server_domain = self._fetch_server_domain() if fetch_server_domain else "keepersecurity.com"

    def health_check(self) -> bool:
        """
        Check whether Keeper Service Mode is reachable.
        """
        try:
            response = self.session.get(f'{self.base_url}/queue/status', timeout=5)
            return response.status_code == 200
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Async command plumbing
    # ------------------------------------------------------------------

    def _submit_and_poll(
        self, command: str, max_wait: int = 10
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Submit a Commander command and poll for the result.

        Returns ``(result_data, None)`` on a completed command (success *or*
        Commander-side error) and ``(None, error_dict)`` when the submit
        itself failed or polling timed out.
        """
        try:
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10,
            )
        except Exception as e:
            return None, {'success': False, 'error': f"Network error: {e}"}

        if response.status_code != 202:
            log_submit_warning(response.status_code, command.split(' ', 1)[0])
            return None, submit_error(response.status_code)

        try:
            request_id = response.json().get('request_id')
        except ValueError:
            request_id = None
        if not request_id:
            return None, {'success': False, 'error': "No request_id received from API"}

        result_data = self._poll_for_result(request_id, max_wait=max_wait)
        if not result_data:
            return None, {'success': False, 'error': "Command timed out or failed"}

        return result_data, None

    def _poll_for_result(self, request_id: str, max_wait: int = 15) -> Optional[Dict[str, Any]]:
        """
        Poll for an async command result until it completes or times out.
        """
        poll_interval = 0.5
        max_poll_interval = 2.0
        elapsed = 0.0

        while elapsed < max_wait:
            try:
                response = self.session.get(
                    f'{self.base_url}/result/{request_id}',
                    timeout=5
                )

                if response.status_code == 200:
                    result = response.json()
                    status = result.get('status')

                    if status == 'success':
                        return result
                    elif status == 'error':
                        error_msg = result.get('error') or result.get('message', 'Unknown error')
                        logger.error(f"Command failed: {error_msg}")
                        return result
                    elif status not in ('pending', 'running'):
                        logger.warning(f"Unknown status: {status}")
                elif response.status_code == 202:
                    logger.debug("Async command still processing, waiting...")
                elif response.status_code in (400, 500):
                    logger.error(f"Poll returned {response.status_code} - returning error immediately")
                    try:
                        error_response = response.json()
                        error_response['http_status'] = response.status_code
                        return error_response
                    except ValueError:
                        return {
                            'status': 'error',
                            'error': f'Server error ({response.status_code})',
                            'http_status': response.status_code
                        }
                else:
                    logger.warning(f"Poll returned status {response.status_code}")

                time.sleep(poll_interval)
                elapsed += poll_interval
                poll_interval = min(poll_interval * 1.5, max_poll_interval)

            except Exception as e:
                logger.error(f"Error polling for result: {e}")
                return None

        logger.warning(f"Polling timed out after {max_wait} seconds")
        return None

    @staticmethod
    def _message_text(result_data: Dict[str, Any]) -> str:
        """Flatten Commander's ``message`` (str or list) into one string."""
        message = result_data.get('message', [])
        if isinstance(message, list):
            return ' '.join(str(m) for m in message)
        return str(message)

    @staticmethod
    def _sanitize_commander_error(error_msg: Any) -> str:
        """
        Strip CLI-only guidance (e.g. "use --force") from a Commander error before showing.
        """
        if isinstance(error_msg, list):
            error_msg = '\n'.join(str(m) for m in error_msg)
        text = str(error_msg)
        cleaned_lines = [
            line for line in text.splitlines()
            if '--force' not in line.lower()
        ]
        return '\n'.join(cleaned_lines).strip() or text.strip()

    @classmethod
    def _error_message(cls, result_data: Dict[str, Any]) -> str:
        """Flatten a Commander error payload into a single string."""
        error_msg = result_data.get('message') or result_data.get('error') or 'Unknown error'
        return cls._sanitize_commander_error(error_msg)

    @classmethod
    def _invitation_pending(cls, result_data: Dict[str, Any]) -> bool:
        """
        Detect Commander's "invitation has been sent" response (requester has
        no Keeper account yet).
        """
        combined = f"{cls._message_text(result_data)} {result_data.get('error', '')}".lower()
        return (
            'invitation has been sent' in combined
            or 'repeat this command when invitation is accepted' in combined
        )

    def _fetch_server_domain(self) -> str:
        """
        Fetch the Keeper server domain using the 'server' command.
        """
        default_domain = "keepersecurity.com"
        try:
            result_data, err = self._submit_and_poll("server", max_wait=10)
            if err or not result_data or result_data.get('status') != 'success':
                logger.warning("Could not fetch Keeper server domain, using default")
                return default_domain
            message = result_data.get('message') or default_domain
            if isinstance(message, list):
                message = message[0] if message else default_domain
            return str(message).strip() or default_domain
        except Exception as e:
            logger.warning(f"Exception fetching server domain: {e}, using default")
            return default_domain

    # ------------------------------------------------------------------
    # Search / lookup
    # ------------------------------------------------------------------

    def _sanitize_search_query(self, query: str) -> str:
        """
        Sanitize search query to prevent command injection.
        """
        if not query:
            return query

        dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']',
                           '!', '\\', '\n', '\r', '\x00', '<', '>', '"', "'"]

        sanitized = query
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')

        return sanitized.strip()

    def search_records(
        self,
        query: str,
        limit: int = 20,
    ) -> Tuple[List[KeeperRecord], Optional[Dict[str, Any]]]:
        """
        Search for records using Service Mode ``search -c r``.

        Returns ``(records, error)``; ``error`` is only set for Commander
        401/403 submit failures so the caller can tell the approver.
        """
        safe_query = self._sanitize_search_query(query)
        if not safe_query:
            logger.debug("Empty query after sanitization")
            return [], None

        result_data, err = self._submit_and_poll(
            f'search -c r "{safe_query}" --format=json', max_wait=30
        )
        if err:
            if err.get('error_code') in ('command_not_allowed', 'commander_unauthorized'):
                return [], err
            logger.debug(f"Record search failed: {err.get('error')}")
            return [], None

        return self._parse_search_records_results(result_data, limit), None

    @staticmethod
    def _pick_search_result_by_uid(data: Any, uid: str) -> Optional[Dict[str, Any]]:
        """
        Return the search row whose ``uid`` exactly matches ``uid``.

        Commander ``search <uid>`` can return multiple rows; the first row is
        not always the requested item.
        """
        if not isinstance(data, list) or not uid:
            return None
        target = str(uid).strip()
        for item in data:
            if isinstance(item, dict) and str(item.get('uid', '')).strip() == target:
                return item
        return None

    @staticmethod
    def _parse_details(details: str) -> Tuple[str, str]:
        """
        Parse Commander's ``details`` string, e.g.
        ``"Type: login, Description: test@gmail.com, Record Category: Nested"``.
        Returns ``(record_type, notes)``.
        """
        record_type = 'login'
        notes = ''
        for part in (details or '').split(', '):
            if part.startswith('Type: '):
                record_type = part.replace('Type: ', '').strip()
            elif part.startswith('Description: '):
                notes = part.replace('Description: ', '').strip()
        return record_type, notes

    @staticmethod
    def _record_is_nsf(details: str) -> bool:
        """
        True if the ``details`` string from a record search result indicates a
        Nested Share Folder record.
        """
        if not details:
            return False
        for part in details.split(', '):
            if part.startswith('Record Category: '):
                category = part.split(': ', 1)[1].strip().lower()
                return category in ('keeperdrive', 'nested')
        return False

    def get_record_by_uid(self, record_uid: str) -> Optional[KeeperRecord]:
        """
        Get record details by UID. Returns None if not found. A folder UID
        returns a KeeperRecord whose ``record_type`` is the folder type so the
        caller can tell the requester to use a folder request instead.
        """
        try:
            result_data, err = self._submit_and_poll(f"search {record_uid} --format=json", max_wait=15)
            if err or not result_data:
                logger.warning(f"Search failed for UID {record_uid}: {err and err.get('error')}")
                return None

            data = result_data.get('data')
            record_data = self._pick_search_result_by_uid(data, record_uid)
            if not record_data:
                logger.warning(f"No exact record match for UID {record_uid}")
                return None

            item_type = record_data.get('type', 'record')
            if item_type in self._FOLDER_ITEM_TYPES:
                logger.warning(
                    f"UID {record_uid} resolved to folder type {item_type!r}; expected a record"
                )
                return KeeperRecord(
                    uid=record_uid,
                    title=record_data.get('name', 'Untitled Folder'),
                    record_type=item_type,
                )

            details = record_data.get('details', '')
            record_type, notes = self._parse_details(details)
            title = record_data.get('name', 'Untitled Record')
            logger.info(f"Found record: {title} (type: {record_type})")

            return KeeperRecord(
                uid=record_data.get('uid', record_uid),
                title=title,
                record_type=record_type,
                notes=notes,
                is_nsf=self._record_is_nsf(details),
            )
        except Exception as e:
            logger.error(f"Failed to get record {record_uid}: {e}", exc_info=True)
            return None

    def get_record_owner(self, record_uid: str) -> Optional[str]:
        """
        Get the owner email of a record.
        """
        try:
            result_data, err = self._submit_and_poll(f"get --format=json {record_uid}", max_wait=15)
            if err or not result_data:
                return None

            data = result_data.get('data')
            if not isinstance(data, dict):
                return None

            for user_perm in data.get('user_permissions', []) or []:
                if user_perm.get('owner', False):
                    owner_email = user_perm.get('username')
                    logger.info(f"Found record owner: {owner_email}")
                    return owner_email

            logger.warning(f"No owner found in user_permissions for record: {record_uid}")
            return None
        except Exception as e:
            logger.error(f"Failed to get record owner for {record_uid}: {e}")
            return None

    @staticmethod
    def _folder_is_nsf(folder_type: str) -> bool:
        return (folder_type or '').strip().lower() == 'nested_share_folder'

    def search_folders(
        self,
        query: str,
        limit: int = 20,
    ) -> Tuple[List[KeeperFolder], Optional[Dict[str, Any]]]:
        """
        Search shared folders (Classic and Nested Share Folders) with
        ``search -c s,d``. Returns ``(folders, error)`` like :meth:`search_records`.
        """
        safe_query = self._sanitize_search_query(query)
        if not safe_query:
            logger.debug("Empty query after sanitization")
            return [], None

        result_data, err = self._submit_and_poll(
            f'search -c s,d "{safe_query}" --format=json', max_wait=30
        )
        if err:
            if err.get('error_code') in ('command_not_allowed', 'commander_unauthorized'):
                return [], err
            logger.debug(f"Folder search failed: {err.get('error')}")
            return [], None

        folders: List[KeeperFolder] = []
        data = result_data.get('data', [])
        if not isinstance(data, list):
            logger.debug(f"Unexpected data format: {type(data)}")
            return folders
        for item in data:
            if not isinstance(item, dict):
                continue
            uid, name = item.get('uid', ''), item.get('name', '')
            folder_type = item.get('type', 'shared_folder')
            if uid and name:
                folders.append(KeeperFolder(
                    uid=uid, name=name, folder_type=folder_type, is_nsf=self._folder_is_nsf(folder_type),
                ))
                if len(folders) >= limit:
                    break
        logger.debug(f"Got {len(folders)} folders from search")
        return folders, None

    def get_folder_by_uid(self, folder_uid: str) -> Optional[KeeperFolder]:
        """
        Get shared folder details by UID. Returns None if not found. A record
        UID returns a KeeperFolder whose ``folder_type`` is ``"record"`` so the
        caller can tell the requester to use a record request instead.
        """
        try:
            result_data, err = self._submit_and_poll(f"search {folder_uid} --format=json", max_wait=15)
            if err or not result_data:
                logger.warning(f"Search failed for UID {folder_uid}: {err and err.get('error')}")
                return None

            folder_data = self._pick_search_result_by_uid(result_data.get('data'), folder_uid)
            if not folder_data:
                logger.warning(f"No exact folder match for UID {folder_uid}")
                return None

            folder_type = folder_data.get('type', 'folder')
            name = folder_data.get('name', 'Untitled Folder')
            if folder_type not in self._FOLDER_ITEM_TYPES:
                logger.warning(f"UID {folder_uid} resolved to non-folder type {folder_type!r}")
                return KeeperFolder(uid=folder_uid, name=name, folder_type='record')

            logger.info(f"Found folder: {name} (type: {folder_type})")
            return KeeperFolder(
                uid=folder_data.get('uid', folder_uid),
                name=name,
                folder_type=folder_type,
                is_nsf=self._folder_is_nsf(folder_type),
            )
        except Exception as e:
            logger.error(f"Failed to get folder {folder_uid}: {e}", exc_info=True)
            return None

    def is_pam_user_folder(self, folder_uid: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Whether the shared folder has rotate-on-expire eligible PAM User records
        (``list-sf <uid> --roe-eligible``). Returns ``(is_pam, error)``; ``error``
        is set only for Commander 401/403 so the caller can report it.
        """
        if not folder_uid:
            return False, None
        result_data, err = self._submit_and_poll(
            f"list-sf {folder_uid} --roe-eligible --format=json", max_wait=10
        )
        if err:
            if err.get('error_code'):
                return False, err
            logger.warning(f"list-sf --roe-eligible failed for {folder_uid}: {err.get('error')}")
            return False, None
        if result_data.get('status') != 'success':
            return False, None
        data = result_data.get('data')
        return isinstance(data, list) and len(data) > 0, None

    def _parse_search_records_results(self, result_data: Dict, limit: int) -> List[KeeperRecord]:
        """
        Parse search command results for records, including Nested Share
        Folder detection so the card can offer the right permission set.
        """
        records: List[KeeperRecord] = []
        data = result_data.get('data', [])
        if not isinstance(data, list):
            logger.debug(f"Unexpected data format: {type(data)}")
            return records

        for item in data:
            if not isinstance(item, dict):
                continue
            uid = item.get('uid', '')
            title = item.get('name', '')
            details = item.get('details', '')
            record_type, notes = self._parse_details(details)

            if uid and title:
                records.append(KeeperRecord(
                    uid=uid,
                    title=title,
                    record_type=record_type,
                    notes=notes,
                    is_nsf=self._record_is_nsf(details),
                ))
                if len(records) >= limit:
                    break

        logger.debug(f"Got {len(records)} records from search")
        return records

    def get_user_teams(self, user_email: str) -> List[str]:
        """
        Return the Keeper team names ``user_email`` belongs to
        (``list-team -v --format json``). Used by multi-channel routing.
        """
        try:
            result_data, err = self._submit_and_poll("list-team -v --format json", max_wait=20)
            if err or not result_data or result_data.get('status') == 'error':
                return []

            data = result_data.get('data', [])
            if not isinstance(data, list):
                return []

            email_lower = user_email.strip().lower()
            teams: List[str] = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                members = {str(m).strip().lower() for m in (item.get('Member', []) or []) if m}
                if email_lower in members and item.get('Name'):
                    teams.append(str(item['Name']).strip())

            logger.debug(f"User {user_email} belongs to teams: {teams}")
            return teams
        except Exception as e:
            logger.error(f"Exception fetching user teams: {e}", exc_info=True)
            return []

    def sync_down(self) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Pull the latest vault state into Commander's cache so records created
        elsewhere are visible. Returns ``(success, error)``; ``error`` is set
        only when Commander rejected the submit.
        """
        result_data, err = self._submit_and_poll("sync-down", max_wait=45)
        if err:
            if err.get('error_code'):
                return False, err
            logger.warning(f"sync-down did not complete: {err.get('error')}")
            return False, None
        if result_data.get('status') == 'success':
            logger.ok("Vault synced from server")
            return True, None
        error = self._error_message(result_data)
        logger.error(f"sync-down failed: {error}")
        if 'session_token_expired' in error or 'session needs to be refreshed' in error.lower():
            return False, {
                'success': False,
                'error_code': 'keeper_session_expired',
                'error': "Commander's Keeper session has expired. Log in again in Commander "
                         "(Service Mode) and retry.",
            }
        return False, None

    # ------------------------------------------------------------------
    # Grant access
    # ------------------------------------------------------------------

    def _format_duration(self, seconds: int) -> str:
        """
        Convert seconds to Keeper share-record ``--expire-in`` format.
        """
        if seconds < 3600:
            return f"{max(1, seconds // 60)}mi"
        elif seconds < 86400:
            return f"{max(1, seconds // 3600)}h"
        elif seconds < 2592000:
            return f"{max(1, seconds // 86400)}d"
        elif seconds < 31536000:
            return f"{max(1, seconds // 2592000)}mo"
        return f"{max(1, seconds // 31536000)}y"

    def _sync_before_share(self, record_uid: str) -> Optional[Dict[str, Any]]:
        """Run sync-down; return an error result only if Commander rejected it."""
        sync_ok, sync_error = self.sync_down()
        if sync_error:
            return {
                'success': False,
                'error_code': sync_error.get('error_code'),
                'error': sync_error.get('error', 'Commander rejected sync-down'),
            }
        if not sync_ok:
            logger.warning(
                "sync-down before sharing did not complete cleanly; "
                "continuing against the current Commander cache for %s", record_uid,
            )
        return None

    def grant_record_access(
        self,
        record_uid: str,
        user_email: str,
        permission: PermissionLevel,
        duration_seconds: Optional[int] = 86400,
        rotate_on_expire: bool = False,
    ) -> Dict[str, Any]:
        """
        Grant access to a Classic record with an optional time limit using
        ``share-record``.
        """
        try:
            sync_error = self._sync_before_share(record_uid)
            if sync_error:
                return sync_error

            # Prevent granting access to the record owner
            record_owner = self.get_record_owner(record_uid)
            if record_owner and user_email.lower() == record_owner.lower():
                return {
                    'success': False,
                    'error': (
                        f"Cannot grant access to record owner ({user_email}). "
                        f"The user already owns this record and has access to it."
                    )
                }

            if permission == PermissionLevel.CHANGE_OWNER:
                command = f"share-record {record_uid} -e {user_email} -a owner --force"
                result_data, err = self._submit_and_poll(command, max_wait=10)
                if err:
                    return err
                if result_data.get('status') == 'success':
                    return {
                        'success': True,
                        'expires_at': 'N/A (Ownership Transfer)',
                        'permission': permission.value,
                        'duration': 'permanent'
                    }
                return {'success': False, 'error': f"Failed to transfer ownership: {self._error_message(result_data)}"}

            permission_flags = []
            if permission == PermissionLevel.CAN_EDIT:
                permission_flags.append("-w")
            elif permission == PermissionLevel.CAN_SHARE:
                permission_flags.append("-s")
            elif permission == PermissionLevel.EDIT_AND_SHARE:
                permission_flags.extend(["-w", "-s"])

            # Revoke first so downgrades (e.g. Edit&Share -> Can Edit) replace
            # the existing share cleanly. Failure here (no existing share) is fine.
            try:
                revoke_data, _ = self._submit_and_poll(
                    f"share-record {record_uid} -e {user_email} -a revoke --force", max_wait=5
                )
                logger.debug(f"Revoke result: {revoke_data}")
            except Exception as e:
                logger.debug(f"Revoke failed or skipped: {e}")

            cmd_parts = ["share-record", record_uid, "-e", user_email, "-a", "grant"]
            cmd_parts.extend(permission_flags)

            if permission in PERMANENT_ONLY_PERMISSIONS or duration_seconds is None:
                expires_at_str = "Never (Permanent)"
            else:
                cmd_parts.extend(["--expire-in", self._format_duration(duration_seconds)])
                expires_at_str = format_local_time(datetime.now() + timedelta(seconds=duration_seconds))
                if rotate_on_expire:
                    cmd_parts.append("--rotate-on-expiration")

            cmd_parts.append("--force")
            result_data, err = self._submit_and_poll(" ".join(cmd_parts), max_wait=10)
            if err:
                return err
            logger.debug(f"Result data: {result_data}")

            if result_data.get('status') == 'success':
                if self._invitation_pending(result_data):
                    logger.info("Share invitation sent to user (not in vault yet)")
                    return {
                        'success': True,
                        'invitation_sent': True,
                        'expires_at': 'Pending Invitation',
                        'permission': permission.value,
                        'duration': 'permanent',
                    }

                return {
                    'success': True,
                    'expires_at': expires_at_str,
                    'permission': permission.value,
                    'duration': 'temporary' if duration_seconds else 'permanent',
                    'rotate_on_expire': bool(
                        rotate_on_expire
                        and duration_seconds is not None
                        and permission not in PERMANENT_ONLY_PERMISSIONS
                    ),
                }

            error_msg = self._error_message(result_data)
            error_lower = error_msg.lower()

            is_rotation_not_configured = (
                "rotation must be already set" in error_lower
                or ("rotate" in error_lower and "expiration" in error_lower and "set on the record" in error_lower)
                or ("--rotate-on-expiration" in error_lower and ("requires" in error_lower or "ineligible" in error_lower))
            )
            if is_rotation_not_configured:
                return {
                    'success': False,
                    'error_code': 'pam_rotation_not_configured',
                    'error': (
                        "Rotation is not configured on this PAM User record.\n\n"
                        "Set up rotation (Gateway + rotation settings) on the record in the "
                        "Keeper Vault first, or set *Rotate credentials when access expires* "
                        "to No and approve again."
                    ),
                }

            if "time-limited access" in error_lower and "re-share" in error_lower:
                return {
                    'success': False,
                    'error': "Unable to grant record access. This user already has temporary access to this record "
                             "which conflicts with the selected permission level.\n\n"
                             "First remove the user's existing access, then grant the new permission."
                }

            if "already" in error_lower and ("shared" in error_lower or "access" in error_lower):
                return {
                    'success': False,
                    'error': "Unable to update record access. This user already has existing permissions "
                             "that conflict with the requested permission level.\n\n"
                             "First revoke the user's existing access, then grant the new permission."
                }

            if "cannot" in error_lower and "permission" in error_lower:
                return {
                    'success': False,
                    'error': "Unable to grant record access. The existing permission conflicts with the new permission.\n\n"
                             "First revoke the user's existing access, then grant the new permission."
                }

            return {'success': False, 'error': f"Failed to grant access: {error_msg}"}

        except Exception as e:
            return {'success': False, 'error': f"Error granting record access: {str(e)}"}

    def grant_nsf_record_access(
        self,
        record_uid: str,
        user_email: str,
        role: NSFPermissionRole,
        duration_seconds: Optional[int] = 86400,
    ) -> Dict[str, Any]:
        """
        Share a Nested Share Folder record with a user via ``nsf-share-record``.
        """
        try:
            sync_error = self._sync_before_share(record_uid)
            if sync_error:
                return sync_error

            if role == NSFPermissionRole.TRANSFER_OWNER:
                result_data, err = self._submit_and_poll(
                    f"nsf-share-record {record_uid} -e {user_email} -a owner -f", max_wait=10
                )
                if err:
                    return err
                if result_data.get('status') == 'success':
                    return {
                        'success': True,
                        'expires_at': 'N/A (Ownership Transfer)',
                        'permission': role.value,
                        'duration': 'permanent',
                    }
                return {'success': False, 'error': f"Failed to transfer ownership: {self._error_message(result_data)}"}

            try:
                self._submit_and_poll(f"nsf-share-record {record_uid} -e {user_email} -a revoke -f", max_wait=5)
            except Exception as e:
                logger.debug(f"NSF record revoke skipped or failed: {e}")

            cmd_parts = ["nsf-share-record", record_uid, "-e", user_email, "-a", "grant", "-r", role.value]
            if duration_seconds is not None:
                cmd_parts.extend(["--expire-in", self._format_duration(duration_seconds)])
                expires_at_str = format_local_time(datetime.now() + timedelta(seconds=duration_seconds))
                duration_label = 'temporary'
            else:
                expires_at_str = "Never (Permanent)"
                duration_label = 'permanent'
            cmd_parts.append("-f")

            result_data, err = self._submit_and_poll(" ".join(cmd_parts), max_wait=10)
            if err:
                return err

            if self._invitation_pending(result_data):
                return {
                    'success': True,
                    'invitation_sent': True,
                    'expires_at': 'Pending Invitation',
                    'permission': role.value,
                    'duration': 'permanent',
                }

            if result_data.get('status') == 'success':
                return {
                    'success': True,
                    'expires_at': expires_at_str,
                    'permission': role.value,
                    'duration': duration_label,
                }

            return {'success': False, 'error': f"Failed to grant access: {self._error_message(result_data)}"}
        except Exception as e:
            return {'success': False, 'error': f"Error granting Nested Share Folder record access: {e}"}

    def grant_folder_access(
        self,
        folder_uid: str,
        user_email: str,
        permission: PermissionLevel,
        duration_seconds: Optional[int] = 86400,
        rotate_on_expire: bool = False,
    ) -> Dict[str, Any]:
        """
        Grant access to a Classic shared folder with ``share-folder``.
        Manage Users / Manage All are always permanent.
        """
        try:
            sync_error = self._sync_before_share(folder_uid)
            if sync_error:
                return sync_error

            flags = {
                PermissionLevel.NO_PERMISSIONS: ["-o", "off", "-p", "off"],
                PermissionLevel.MANAGE_USERS: ["-o", "on", "-p", "off"],
                PermissionLevel.MANAGE_RECORDS: ["-o", "off", "-p", "on"],
                PermissionLevel.MANAGE_ALL: ["-o", "on", "-p", "on"],
            }.get(permission, ["-o", "off", "-p", "off"])
            cmd_parts = ["share-folder", folder_uid, "-e", user_email, "-a", "grant", *flags]

            if permission in FOLDER_PERMANENT_ONLY_PERMISSIONS:
                duration_seconds = None
            if duration_seconds is None:
                expires_at_str = "Never (Permanent)"
            else:
                cmd_parts.extend(["--expire-in", self._format_duration(duration_seconds)])
                expires_at_str = format_local_time(datetime.now() + timedelta(seconds=duration_seconds))
                if rotate_on_expire:
                    cmd_parts.append("--rotate-on-expiration")
            cmd_parts.append("-f")

            result_data, err = self._submit_and_poll(" ".join(cmd_parts), max_wait=10)
            if err:
                return err
            logger.debug(f"Result data: {result_data}")

            # share-folder reports "invitation sent" as an HTTP 400 error
            if self._invitation_pending(result_data):
                logger.info("Share invitation sent to user (not in vault yet)")
                return {
                    'success': True,
                    'invitation_sent': True,
                    'expires_at': 'Pending Invitation',
                    'permission': permission.value,
                    'duration': 'permanent',
                }

            if result_data.get('http_status') == 400:
                return {
                    'success': False,
                    'error': "Unable to grant folder access. This user may already have temporary access to this "
                             "folder which conflicts with the selected permission level.\n\n"
                             "First remove the user's existing access, then grant the new permission.",
                }

            if result_data.get('status') == 'success':
                return {
                    'success': True,
                    'expires_at': expires_at_str,
                    'permission': permission.value,
                    'duration': 'temporary' if duration_seconds else 'permanent',
                    'rotate_on_expire': bool(rotate_on_expire and duration_seconds is not None),
                }

            error_msg = self._error_message(result_data)
            error_lower = error_msg.lower()
            if (
                "rotation must be already set" in error_lower
                or ("rotate" in error_lower and "expiration" in error_lower and "set on the record" in error_lower)
            ):
                return {
                    'success': False,
                    'error_code': 'pam_rotation_not_configured',
                    'error': (
                        "Rotation is not configured for this PAM User folder.\n\n"
                        "Set up rotation on the records in this folder in the Keeper Vault first, "
                        "or set *PAM credential rotation* to No and approve again."
                    ),
                }

            time_limited_conflict = "time-limited access" in error_lower and (
                "manage" in error_lower or "re-share" in error_lower
            )
            if time_limited_conflict or ("user share" in error_lower and "failed" in error_lower):
                return {
                    'success': False,
                    'error': "Unable to grant folder access. This user already has temporary access to this folder "
                             "which conflicts with the selected permission level.\n\n"
                             "First remove the user's existing access, then grant the new permission.",
                }

            return {'success': False, 'error': f"Failed to grant access: {error_msg}"}
        except Exception as e:
            return {'success': False, 'error': f"Error granting folder access: {e}"}

    def grant_nsf_folder_access(
        self,
        folder_uid: str,
        user_email: str,
        role: NSFPermissionRole,
        duration_seconds: Optional[int] = 86400,
    ) -> Dict[str, Any]:
        """Share a Nested Share Folder with a user via ``nsf-share-folder``."""
        try:
            sync_error = self._sync_before_share(folder_uid)
            if sync_error:
                return sync_error

            cmd_parts = ["nsf-share-folder", folder_uid, "-e", user_email, "-a", "grant", "-r", role.value]
            if duration_seconds is not None:
                cmd_parts.extend(["--expire-in", self._format_duration(duration_seconds)])
                expires_at_str = format_local_time(datetime.now() + timedelta(seconds=duration_seconds))
                duration_label = 'temporary'
            else:
                expires_at_str = "Never (Permanent)"
                duration_label = 'permanent'

            result_data, err = self._submit_and_poll(" ".join(cmd_parts), max_wait=10)
            if err:
                return err

            if self._invitation_pending(result_data):
                return {
                    'success': True,
                    'invitation_sent': True,
                    'expires_at': 'Pending Invitation',
                    'permission': role.value,
                    'duration': 'permanent',
                }

            if result_data.get('status') == 'success':
                return {
                    'success': True,
                    'expires_at': expires_at_str,
                    'permission': role.value,
                    'duration': duration_label,
                }

            return {'success': False, 'error': f"Failed to grant access: {self._error_message(result_data)}"}
        except Exception as e:
            return {'success': False, 'error': f"Error granting Nested Share Folder access: {e}"}
