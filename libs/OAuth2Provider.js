var util = require('util');
var AuthProviderAbstract = require('vectorwatch-authprovider-abstract');
var Promise = require('bluebird');
var url = require('url');
var OAuth2 = require('oauth').OAuth2;

function OAuth2Provider(storageProvider, options) {
    AuthProviderAbstract.call(this, storageProvider);
    this.setOptions(options, [
        'clientId', 'clientSecret',
        'authorizeUrl', 'accessTokenUrl',
        'callbackUrl'
    ]);

    this.protocol = 'OAuth';
    this.version = '2.0';

    var urlParts = url.parse(this.options.accessTokenUrl);
    var baseUrl = urlParts.protocol +
        (urlParts.slashes ? '//' : '') +
        (urlParts.auth ? (urlParts.auth + '@') : '') +
        urlParts.host;
    var accessTokenPath = urlParts.path;

    this.client = new OAuth2(
        this.options.clientId,
        this.options.clientSecret,
        baseUrl,
        null,
        accessTokenPath
    );
}

OAuth2Provider.prototype.setOptions = function(options, required) {
    this.options = {};
    var optionNames = Object.keys(options), _this;
    required.forEach(function(requiredOptionName) {
        if (optionNames.indexOf(requiredOptionName) < 0) {
            throw new Error('Option ' + requiredOptionName + ' is required.');
        }
    });

    optionNames.forEach(function(optionName) {
        _this.options[optionName] = options[optionName];
    });
};

OAuth2Provider.prototype.getAuthTokensAsync = function(credentials) {
    var _this = this;
    var credentialsKey = this.getCredentialsKey(credentials);

    return this.getStorageProvider().getAuthTokensByCredentialsKeyAsync(credentialsKey).then(function(authTokens) {
        if (authTokens) {
            return authTokens;
        }

        return new Promise(function(resolve, reject) {
            _this.client.getOAuthAccessToken(code, {
                redirect_uri: _this.options.callbackUrl,
                grant_type: _this.options.grantType || 'authorization_code'
            }, function(err, access_token, refresh_token) {
                if (err) {
                    return reject(err);
                }

                var authTokens = {
                    access_token: access_token,
                    refresh_token: refresh_token
                };

                _this.getStorageProvider().storeAuthTokensAsync(credentialsKey, authTokens).then(function() {
                    resolve(authTokens);
                }).catch(function (err) {
                    reject(err);
                });
            });
        });
    });
};

OAuth2Provider.prototype.getCredentialsKey = function(credentials) {
    return credentials.state;
};

OAuth2Provider.prototype.getLoginUrlAsync = function() {
    var hmac = require('crypto').createHmac('sha1', this.options.clientSecret);
    hmac.update(JSON.stringify([Date.now(), Math.random()]));
    var state = hmac.digest('hex');

    var parsedUrl = url.parse(this.options.authorizeUrl, true);
    parsedUrl.query.redirect_uri = this.options.callbackUrl;
    parsedUrl.query.state = state;
    parsedUrl.query.client_id = this.options.clientId;
    delete parsedUrl.search;

    return Promise.resolve(url.format(parsedUrl));
};

module.exports = OAuth2Provider;