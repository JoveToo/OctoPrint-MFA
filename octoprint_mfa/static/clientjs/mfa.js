(function (global, factory) {
    if (typeof define === "function" && define.amd) {
        define(["OctoPrintClient"], factory);
    } else {
        factory(global.OctoPrintClient);
    }
})(this, function (OctoPrintClient) {
    var OctoPrintMfaClient = function (base) {
        this.base = base;
    };

    OctoPrintMfaClient.prototype.getPasskeys = function(opts) {
        return this.base.get(OctoPrintClient.prototype.getSimpleApiUrl("mfa") + "?passkeys=true", opts)
    }
    
    OctoPrintMfaClient.prototype.generateAuthenticationOptions = function(opts) {
        return this.base.get(OctoPrintClient.prototype.getSimpleApiUrl("mfa") + "?generate-authentication-options=true", opts);
    }

    OctoPrintMfaClient.prototype.verifyAuthentication = function(data, opts) {
        return this.base.simpleApiCommand("mfa", "verify-authentication", data, opts);
    }

    OctoPrintMfaClient.prototype.generateRegistrationOptions = function(opts) {
        return this.base.get(OctoPrintClient.prototype.getSimpleApiUrl("mfa") + "?generate-registration-options=true", opts);
    }

    OctoPrintMfaClient.prototype.verifyRegistration = function(data, opts) {
        return this.base.simpleApiCommand("mfa", "verify-registration", data, opts);
    }

    OctoPrintMfaClient.prototype.startRegistration = function(data) {
        return SimpleWebAuthnBrowser.startRegistration(data);
    }

    OctoPrintMfaClient.prototype.deletePasskey = function(data, opts) {
        return this.base.simpleApiCommand("mfa", "remove-credential", data, opts);
    }

    OctoPrintClient.registerPluginComponent("mfa", OctoPrintMfaClient);
    return OctoPrintMfaClient;
});