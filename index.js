var util = require("util");
var url = require("url");
var tls = require('tls');
var OAuth = require("oauth").OAuth;

module.exports = function (everyauth) {
  var oauth = everyauth.oauth =
  everyauth.everymodule.submodule('oauth')
  .on('setup', function (module) {
    module.oauth = new OAuth(
        module.oauthHost() + module.requestTokenPath()
      , module.oauthHost() + module.accessTokenPath()
      , module.consumerKey()
      , module.consumerSecret()
      , '1.0', null, 'HMAC-SHA1');
  })
  .configurable({
      apiHost: 'e.g., https://api.twitter.com'
    , oauthHost: 'the host for the OAuth provider'
    , requestTokenPath: "the path on the OAuth provider's domain where we request the request token, e.g., /oauth/request_token"
    , accessTokenPath: "the path on the OAuth provider's domain where we request the access token, e.g., /oauth/access_token"
    , authorizePath: 'the path on the OAuth provider where you direct a visitor to login, e.g., /oauth/authorize'
    , sendCallbackWithAuthorize: 'whether you want oauth_callback=... as a query param send with your request to /oauth/authorize'
    , consumerKey: 'the api key provided by the OAuth provider'
    , consumerSecret: 'the api secret provided by the OAuth provider'
    , myHostname: 'e.g., http://localhost:3000 . Notice no trailing slash'
    , alwaysDetectHostname: 'does not cache myHostname once. Instead, re-detect it on every request. Good for multiple subdomain architectures'
    , redirectPath: 'Where to redirect to after a failed or successful OAuth authorization'
    , convertErr: '(DEPRECATED) a function (data) that extracts an error message from data arg, where `data` is what is returned from a failed OAuth request'
    , authCallbackDidErr: 'Define the condition for the auth module determining if the auth callback url denotes a failure. Returns true/false.'
  })

  // Declares a GET route that is aliased
  // as 'entryPath'. The handler for this route
  // triggers the series of steps that you see
  // indented below it.
  .get('entryPath',
       'the link a user follows, whereupon you redirect them to the 3rd party OAuth provider dialog - e.g., "/auth/twitter"')
    .step('getRequestToken')
      .description('asks OAuth Provider for a request token')
      .accepts('req res next')
      .promises('token tokenSecret')
    .step('storeRequestToken')
      .description('stores the request token and secret in the session')
      .accepts('req token tokenSecret')
      .promises(null)
    .step('redirectToProviderAuth')
      .description('sends the user to authorization on the OAuth provider site')
      .accepts('res token')
      .promises(null)

  .get('callbackPath',
       'the callback path that the 3rd party OAuth provider redirects to after an OAuth authorization result - e.g., "/auth/twitter/callback"')
    .step('extractTokenAndVerifier')
      .description('extracts the request token and verifier from the url query')
      .accepts('req res next')
      .promises('requestToken verifier')
    .step('getSession')
      .accepts('req')
      .promises('session')
    .step('rememberTokenSecret')
      .description('retrieves the request token secret from the session')
      .accepts('session')
      .promises('requestTokenSecret')
    .step('getAccessToken')
      .description('requests an access token from the OAuth provider')
      .accepts('requestToken requestTokenSecret verifier')
      .promises('accessToken accessTokenSecret params')
    .step('fetchOAuthUser')
      .accepts('accessToken accessTokenSecret params')
      .promises('oauthUser')
    .step('assignOAuthUserToSession')
      .accepts('oauthUser session')
      .promises('session')
    .step('findOrCreateUser')
      .accepts('session accessToken accessTokenSecret oauthUser')
      .promises('user')
    .step('compileAuth')
      .accepts('accessToken accessTokenSecret oauthUser user')
      .promises('auth')
    .step('addToSession')
      .accepts('session auth')
      .promises(null)
    .step('sendResponse')
      .accepts('res')
      .promises(null)

  .getRequestToken( function (req, res, next) {

    // Automatic hostname detection + assignment
    if (!this._myHostname || this._alwaysDetectHostname) {
      this.myHostname(extractHostname(req));
    }

    var p = this.Promise();
    var params = {oauth_callback: this._myHostname + this._callbackPath};
    var additionalParams = this.moreRequestTokenQueryParams;
    var param;

    if (additionalParams) for (var k in additionalParams) {
      param = additionalParams[k];
      if ('function' === typeof param) {
        // e.g., for facebook module, param could be
        // function () {
        //   return this._scope && this.scope();
        // }
        additionalParams[k] = // cache the function call
          param = param.call(this);
      }
      if ('function' === typeof param) {
        // this.scope() itself could be a function
        // to allow for dynamic scope determination - e.g.,
        // function (req, res) {
        //   return req.session.onboardingPhase; // => "email"
        // }
        param = param.call(this, req, res);
      }
      params[k] = param;
    }
    this.oauth.getOAuthRequestToken(params, function (err, token, tokenSecret, params) {
      if (err) {
        return p.fail(err);
      }
      p.fulfill(token, tokenSecret);
    });
    return p;
  })
  .storeRequestToken( function (req, token, tokenSecret) {
    var sess = req.session;
    var _auth = sess.auth || (sess.auth = {});
    var _provider = _auth[this.name] || (_auth[this.name] = {});
    _provider.token = token;
    _provider.tokenSecret = tokenSecret;
  })
  .redirectToProviderAuth( function (res, token) {
    // Note: Not all oauth modules need oauth_callback as a uri query parameter. As far as I know, only readability's
    // module needs it as a uri query parameter. However, in cases such as twitter, it allows you to over-ride
    // the callback url settings at dev.twitter.com from one place, your app code, rather than in two places -- i.e.,
    // your app code + dev.twitter.com app settings.
    var redirectTo = this._oauthHost + this._authorizePath + '?oauth_token=' + token;
    if (this._sendCallbackWithAuthorize) {
      redirectTo += '&oauth_callback=' + this._myHostname + this._callbackPath;
    }
    this.redirect(res, redirectTo);
  })

  // Steps for GET `callbackPath`
  .extractTokenAndVerifier( function (req, res, next) {
    if (this._authCallbackDidErr && this._authCallbackDidErr(req)) {
      return this.halt(next(new this.AuthCallbackError(req)));
    }

    var promise = this.Promise();

    var parsedUrl = url.parse(req.url, true);
    var query = parsedUrl.query;
    var requestToken = query && query.oauth_token;
    var verifier = query && query.oauth_verifier;

    var sess = req.session;
    var _auth = sess.auth || (sess.auth = {});
    var pluginName = this.name;
    var mod = _auth[pluginName] || (_auth[pluginName] = {});

    mod.verifier = verifier;
    sess.save( function (err) {
      if (err) return promise.fail(err);
      promise.fulfill(requestToken, verifier);
    });
    return promise;
  })
  .getSession( function(req) {
    return req.session;
  })
  .rememberTokenSecret( function (sess) {
    return sess && sess.auth && sess.auth[this.name] && sess.auth[this.name].tokenSecret;
  })
  .getAccessToken( function (reqToken, reqTokenSecret, verifier, data) {
    var promise = this.Promise();
    var pluginName = this.name;
    this.oauth.getOAuthAccessToken(reqToken, reqTokenSecret, verifier, function (err, accessToken, accessTokenSecret, params) {
      if (! err) {
        return promise.fulfill(accessToken, accessTokenSecret, params);
      }

      // We might receive an error, if a user manually kicked off a request to
      // the callbackPath, in addition to the Provider sending a redirect to
      // the callbackPath. This results in 2 competing requests for an
      // access_token, with the later request failing because an access_token
      // can only be requested once with a nonce.
      // In this case, we should try to have the failing access_token request
      // try to reload the session until we see the access token the other
      // request retrieved. Once we do so, we should pass control along to the
      // next express route/middleware handler
      var session = data.session;
      tryTimes(5, 100, function (retry) {
        session.reload( function (reloadErr) {
          if (reloadErr) {
            promise.fail(reloadErr);
            return retry(false);
          }
          var sessAuth = session.auth[pluginName];
          if (! sessAuth.accessToken) {
            promise.fail(err);
            return retry();
          }
          // TODO Cleanup promise
          this._sendResponse(data.res, data);
          return retry(false);
        });
      }, 100);
    });
    return promise;
  })
  .assignOAuthUserToSession( function (oauthUser, session) {
    session.auth[this.name].user = oauthUser;
    return session;
  })
  .compileAuth( function (accessToken, accessTokenSecret, oauthUser, user) {
    return {
        accessToken: accessToken
      , accessTokenSecret: accessTokenSecret
      , oauthUser: oauthUser
      , user: user
    };
  })
  .addToSession( function (sess, auth) {
    var promise = this.Promise();
    var _auth = sess.auth;
    var mod = _auth[this.name];
    _auth.loggedIn = true;
    _auth.userId || (_auth.userId = auth.user[this._userPkey]);
    mod.user = auth.oauthUser;
    mod.accessToken = auth.accessToken;
    mod.accessTokenSecret = auth.accessTokenSecret;
    // this._super() ?
    sess.save( function (err) {
      if (err) return promise.fail(err);
      promise.fulfill();
    });
    return promise;
  })
  .sendResponse( function (res, data) {
    var redirectTo = this._redirectPath;
    if (redirectTo) {
      this.redirect(res, redirectTo);
    } else {
      data.next();
    }
  });

  // Defaults inherited by submodules
  oauth
    .requestTokenPath('/oauth/request_token')
    .authorizePath('/oauth/authorize')
    .accessTokenPath('/oauth/access_token')
    .sendCallbackWithAuthorize(true);

  oauth.moreRequestTokenQueryParams = {};
  oauth.cloneOnSubmodule.push('moreRequestTokenQueryParams');

  // Add or over-write existing query params that
  // get tacked onto the oauth authorize url.
  oauth.requestTokenQueryParam = function (key, val) {
    if (arguments.length === 1 && key.constructor == Object) {
      for (var k in key) {
        this.requestTokenQueryParam(k, key[k]);
      }
      return this;
    }
    if (val)
      this.moreRequestTokenQueryParams[key] = val;
    return this;
  };

  /* Errors */

  oauth.AuthCallbackError = AuthCallbackError;

  return oauth;
};

function AuthCallbackError (req) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'AuthCallbackError';
  this.message = '';
  this.req = req;
}
util.inherits(AuthCallbackError, Error);

function extractHostname (req) {
  var headers = req.headers;
  var protocol = (req.connection.server instanceof tls.Server ||
                 (req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'].slice(0,5) === 'https'))
               ? 'https://'
               : 'http://';
  var host = headers.host;
  return protocol + host;
}

function tryTimes(n, ms, fn) {
  fn(done);
  function retry(shouldRetry) {
    if (shouldRetry === false) return;
    if (n-1 > 0) {
      setTimeout(function () {
        tryTimes(n-1, ms, fn);
      }, ms);
    }
  }
}
