# coding=utf-8
from __future__ import absolute_import

import webauthn
import logging
import octoprint.plugin
import flask_login
import flask_login.utils
import flask
import base64
import json
from flask import make_response, render_template, abort
from octoprint_mfa.mfa_user_manager import MFAUserManager

from octoprint.server import NO_CONTENT

from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    RegistrationCredential,
)


class MFAPlugin(
        octoprint.plugin.AssetPlugin,
        octoprint.plugin.SettingsPlugin,
        octoprint.plugin.SimpleApiPlugin,
        octoprint.plugin.TemplatePlugin,
        octoprint.plugin.UiPlugin
        ):
    """
        octoprint.plugin.AssetPlugin methods
    """
    def get_assets(self):
        return dict(
            js=["js/mfa.js"],
            clientjs=["clientjs/mfa.js"]
        )

    """
        octoprint.plugin.SettingsPlugin methods
    """
    def get_settings_restricted_paths(self):
        """
        Plugin set restricted paths of config.yaml
        """
        return dict(admin=[["plugins", "mfa"], ])

    """
        octoprint.plugin.TemplatePlugin
    """
    def get_template_configs(self):
        return [
            dict(
                 type="settings",
                 template="mfa_settings.jinja2"
            ),
            dict(
                type="usersettings",
                template="mfa_usersettings.jinja2",
                name="Passkeys"
            )
        ]

    """
        octoprint.plugin.UiPlugin methods  
    """
    def will_handle_ui(self, request):
        handle_ui = request.path == "/"
        user = flask_login.current_user
        try:
            handle_ui = handle_ui and user.is_anonymous()
        except Exception:
            handle_ui = True
        return handle_ui

    def get_ui_permissions(self):
        return []

    def on_ui_render(self, now, request, render_kwargs):
        return make_response(
            render_template("mfa_login.jinja2", **render_kwargs)
            )
    """
        octoprint.plugin.SimpleApiPlugin methods  
    """
    def on_api_get(self, request):
        if request.values.get("generate-registration-options") is not None:
            options = webauthn.generate_registration_options(
                rp_id="localhost",
                rp_name="OctoPrint",
                user_id=flask_login.utils.current_user.get_name(),
                user_name=flask_login.utils.current_user.get_name(),
                authenticator_selection=AuthenticatorSelectionCriteria(
                    resident_key=ResidentKeyRequirement.REQUIRED,
                    )
                )

            self._stored_challenge = options.challenge

            return webauthn.options_to_json(options)

        if request.values.get("generate-authentication-options") is not None:
            options = webauthn.generate_authentication_options(
                rp_id="localhost"
                )

            return webauthn.options_to_json(options)
        
        if request.values.get("passkeys") is not None:
            return flask.jsonify(
                passkeys=list(
                    map(lambda x: {
                        "name": x["name"],
                        "credential_id": x["credential_id"],
                        "rp_id": x["rp_id"]
                    },
                    flask_login.utils.current_user.get_webauthnCredentials()
                    )
                )
            )
        return abort(404)
    
    def get_api_commands(self):
        return {"verify-registration": [], "remove-credential": ["data"]}

    def on_api_command(self, command, data):
        current_user = flask_login.utils.current_user
        user_id = current_user.get_name()
        if not user_id:
            return flask.abort(403)

        if command == "verify-registration":
            try:
                result = webauthn.verify_registration_response(
                    credential=RegistrationCredential.parse_raw(
                        json.dumps(data["data"])
                    ),
                    expected_challenge=self._stored_challenge,
                    expected_rp_id="localhost",
                    expected_origin="http://localhost:5000",
                )
            except Exception as e:
                self._logger.info(
                    "Registration verification failed with " + str(e)
                    )
                return flask.abort(401)

            credential = {
                "name": data["passkeyName"],
                "credential_id": 
                    base64.b64encode(result.credential_id).decode("utf-8"),
                "credential_public_key": 
                    base64.b64encode(result.credential_public_key).decode(
                    "utf-8"
                    ),
                "sign_count": result.sign_count,
                "rp_id": "localhost"
            }

            self._user_manager.add_credential_to_user(
                current_user.get_name(),
                credential
                )

            return flask.jsonify(success=True, credential=credential)

        if command == "remove-credential":
            result = self._user_manager.remove_credential_from_user(
                current_user.get_name(),
                data["data"]
            )

            return flask.jsonify(success=result)

        return NO_CONTENT


def user_factory_hook(components, settings, *args, **kwargs):
    """
        User factory hook, to initialise the MFA plugin
    """
    logging.getLogger("octorprint.plugsin." + __name__).info(
        "Multi Factor Authentication Provider"
        )

    return MFAUserManager(components, settings)


__plugin_name__ = "MFA"
__plugin_implementation__ = MFAPlugin()
__plugin_pythoncompat__ = ">=3,<4"
__plugin_hooks__ = {
    "octoprint.access.users.factory": user_factory_hook
}
