"""
This file creates the MFA User Manager
"""

import logging
import os
import shutil

from octoprint.access.users import (
    UserManager,
    FilebasedUserManager,
    User,
    CorruptUserStorage,
    UnknownUser,
    UserAlreadyExists,
    )
from octoprint.access.groups import FilebasedGroupManager
from octoprint.util import get_class, yaml
from octoprint.util import atomic_write


class MFAUserManager(FilebasedUserManager):
    """
    MFAUserManager replaced FilebasedUserManager
    """
    logger = logging.getLogger("octoprint.plugsin." + __name__)

    def __init__(self, components, settings):
        MFAUserManager.logger.info("Initializing")
        self._components = components
        self._settings = settings

        group_manager_name = settings.get(["accessControl", "groupManager"])
        try:
            clazz = get_class(group_manager_name)
            group_manager = clazz()
        except AttributeError:
            self.logger.info(
                "Could not instantiate group manager {}, "
                "falling back to FilebasedGroupManager!".format(
                    group_manager_name
                    ),
                err=True,
            )
            group_manager = FilebasedGroupManager()

        FilebasedUserManager.__init__(self, group_manager)

    def _load(self):
        if os.path.exists(self._userfile) and os.path.isfile(self._userfile):
            data = yaml.load_from_file(path=self._userfile)

            if not data or not isinstance(data, dict):
                self._logger.fatal(
                    "{} does not contain a valid map of users. Fix "
                    "the file, or remove it, then restart OctoPrint.".format(
                        self._userfile
                    )
                )
                raise CorruptUserStorage()

            version = data.pop("_version", 1)
            if version != self.FILE_VERSION:
                self._logger.info(
                    f"Making a backup of the users.yaml file before migrating from version {version} to {self.FILE_VERSION}"
                )
                shutil.copy(
                    self._userfile,
                    os.path.splitext(self._userfile)[0] + f".v{version}.yaml",
                )
                self._dirty = True

            for name, attributes in data.items():
                if not isinstance(attributes, dict):
                    continue

                permissions = []
                if "permissions" in attributes:
                    permissions = attributes["permissions"]

                if "groups" in attributes:
                    groups = set(attributes["groups"])
                else:
                    groups = {self._group_manager.user_group}

                # migrate from roles to permissions
                if "roles" in attributes and "permissions" not in attributes:
                    self._logger.info(
                        f"Migrating user {name} to new granular permission system"
                    )

                    groups |= set(self._migrate_roles_to_groups(attributes["roles"]))
                    self._dirty = True

                apikey = None
                if "apikey" in attributes:
                    apikey = attributes["apikey"]
                settings = {}
                if "settings" in attributes:
                    settings = attributes["settings"]

                webauthnCredentials = []
                if "webauthnCredentials" in attributes:
                    webauthnCredentials = attributes["webauthnCredentials"]

                self._users[name] = MFAUser(
                    username=name,
                    passwordHash=attributes["password"],
                    active=attributes["active"],
                    permissions=self._to_permissions(*permissions),
                    groups=self._to_groups(*groups),
                    apikey=apikey,
                    settings=settings,
                    webauthnCredentials=webauthnCredentials
                )
                for sessionid in self._sessionids_by_userid.get(name, set()):
                    if sessionid in self._session_users_by_session:
                        self._session_users_by_session[sessionid].update_user(
                            self._users[name]
                        )

            if self._dirty:
                self._save()

            self.cleanup_legacy_hashes()

            self._customized = True
        else:
            self._customized = False

    def _save(self, force=False):
        if not self._dirty and not force:
            return

        data = {"_version": self.FILE_VERSION}
        for name, user in self._users.items():
            if not user or not isinstance(user, MFAUser):
                continue

            data[name] = {
                "password": user._passwordHash,
                "active": user._active,
                "groups": self._from_groups(*user._groups),
                "permissions": self._from_permissions(*user._permissions),
                "apikey": user._apikey,
                "settings": user._settings,
                "webauthnCredentials": user._webauthnCredentials,
                # TODO: deprecated, remove in 1.5.0
                "roles": user._roles,
            }

        with atomic_write(
            self._userfile, mode="wt", permissions=0o600, max_permissions=0o666
        ) as f:
            yaml.save_to_file(data, file=f, pretty=True)
            self._dirty = False
        self._load()

    def add_credential_to_user(self, username, credential, save=True, notify=True):
        if username not in self._users:
            raise UnknownUser(username)

        if self._users[username].add_credential(credential):
            self._dirty = True

            if save:
                self._save()

            if notify:
                self._trigger_on_user_modified(username)

    def remove_credential_from_user(self, username, credential, save=True, notify=True):
        if username not in self._users:
            raise UnknownUser(username)

        if self._users[username].remove_credential(credential):
            self._dirty = True

            if save:
                self._save()

            if notify:
                self._trigger_on_user_modified(username)

            return True

        return False
    
    def find_credential_from_user(self, username, credential_id):
        if username not in self._users:
            raise UnknownUser(username)
        
        for cred in self._users[username]._webauthnCredentials:
            if cred["credential_id"] == credential_id:
                return cred
        
        raise UnknownUser(username)

    def update_sign_count_on_credential(
            self,
            username,
            credential_id,
            sign_count,
            ):
        if username not in self._users:
            raise UnknownUser(username)

        self._dirty = self._users[username].update_credential_sign_count(
            credential_id, sign_count)

        if (self._dirty):
            self._save()

    def add_user(
        self,
        username,
        password,
        active=False,
        permissions=None,
        groups=None,
        apikey=None,
        overwrite=False,
    ):
        if permissions is None:
            permissions = []
        permissions = self._to_permissions(*permissions)

        if groups is None:
            groups = self._group_manager.default_groups
        groups = self._to_groups(*groups)

        if username in self._users and not overwrite:
            raise UserAlreadyExists(username)

        if not username.strip() or username != username.strip():
            raise Exception("Username '%s' is invalid" % username)

        self._users[username] = MFAUser(
            username,
            UserManager.create_password_hash(password, settings=self._settings),
            active,
            permissions,
            groups,
            apikey=apikey,
        )
        self._dirty = True
        self._save()


class MFAUser(User):
    def __init__(
        self,
        username,
        passwordHash,
        active,
        permissions=None,
        groups=None,
        apikey=None,
        settings=None,
        webauthnCredentials=None,
    ):
        User.__init__(
            self,
            username,
            passwordHash,
            active,
            permissions,
            groups,
            apikey,
            settings
        )
        if (webauthnCredentials is None):
            webauthnCredentials = []

        self._webauthnCredentials = webauthnCredentials
    
    @property
    def has_webauthnCredentials(self):
        return self._webauthnCredentials.count() > 0
    
    def get_webauthnCredentials(self):
        return self._webauthnCredentials

    def add_credential(self, credential):
        self._webauthnCredentials.append(credential)

        dirty = True

        return dirty

    def remove_credential(self, credential):
        dirty = False
        length = len(self._webauthnCredentials)
        self._webauthnCredentials = [
            c for c in self._webauthnCredentials if
            c["credential_id"] != credential["credential_id"]
            ]

        if (length > len(self._webauthnCredentials)):
            dirty = True

        return dirty

    def update_credential_sign_count(self, credential, count):
        for c in self._webauthnCredentials:
            if (c["credential_id"] == credential):
                if (count >= c["sign_count"]):
                    c["sign_count"] = count
                    return True

        return False




