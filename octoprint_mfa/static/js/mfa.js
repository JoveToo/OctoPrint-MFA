$(function () {
    function UserMfaViewModel(parameters) {
        var self = this;

        self.loginState = parameters[0];

        self.passkeys = new ItemListHelper(
            "plugin.mfa.passkeys",
            {
                app: function (a, b) {
                    // sorts ascending
                    if (a["app_id"].toLowerCase() < b["app_id"].toLowerCase()) return -1;
                    if (a["app_id"].toLowerCase() > b["app_id"].toLowerCase()) return 1;
                    return 0;
                }
            },
            {},
            "app",
            [],
            [],
            5
        );

        self.passkeyName = ko.observable();

        self.requestData = function () {
            OctoPrint.plugins.mfa.getPasskeys().done(self.fromResponse);
        };

        self.fromResponse = function (response) {
            self.passkeys.updateItems(response.passkeys);
        };

        self.onUserSettingsShown = function () {
            self.requestData();
        }

        self.createPasskey = function() {
            OctoPrint.plugins.mfa.
                generateRegistrationOptions()
                .then(function(options) {
                    return OctoPrint.plugins.mfa.startRegistration(options)
                })
                .then(function(authResponse) {
                    return OctoPrint.plugins.mfa.verifyRegistration({"passkeyName" : self.passkeyName(), "data": authResponse})
                }
                )
                .then(function(result){
                    if (result["success"])
                        self.requestData();
                })
                .fail((err) => {
                    var test = err;
                });
        };

        self.deletePasskey = function(data) {
            OctoPrint.plugins.mfa.deletePasskey({"data" : data})
            .then(function(result) {
                if (result["success"])
                    self.requestData();
            }
            )
        }
    }

    OCTOPRINT_VIEWMODELS.push([
        UserMfaViewModel,
        ["loginStateViewModel"],
        ["#usersettings_plugin_mfa"]
    ]);
});