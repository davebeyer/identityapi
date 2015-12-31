/// <reference path="./typings/tsd.d.ts" />
var swig_1 = require('swig');
var passport = require('passport');
var session = require('express-session');
var FacebookStrategy = require('passport-facebook').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var path = require('path');
//
// Passport session setup.
//   To support persistent signin sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete Facebook profile is serialized
//   and deserialized.
//
passport.serializeUser(function (user, done) {
    done(null, user);
});
passport.deserializeUser(function (obj, done) {
    done(null, obj);
});
//
// Lighthouse Session Manager
//
var LHSessionMgr = (function () {
    function LHSessionMgr(appName, authConfig, options) {
        var options = options || {};
        this.appName = appName;
        this.authConfig = authConfig;
        this.klass = options.klass || "lh-identity";
        this.hostURL = options.hostURL || "http://localhost:3000";
        this.authPath = options.authPath || "/auth";
        this.successPath = options.successPath || '/';
        this.failurePath = options.failurePath || this.authPath + '/signin';
        this.signinTmpl = swig_1.compileFile(path.resolve(__dirname, 'signin.tmpl.html'));
        var strategy;
        var self = this;
        if (authConfig.facebook) {
            if (!authConfig.facebook.callbackURL) {
                authConfig.facebook.callbackURL = this.hostURL + '/' + this.authPath + '/facebook/callback';
            }
            // For Facebook, need to specify profileFields to fetch.  First, create copy
            var fbAuthConfig = (JSON.parse(JSON.stringify(authConfig.facebook)));
            // Then add profileFields
            fbAuthConfig.profileFields = ["id", "name", "displayName", "photos", "profileUrl", "emails", "gender"];
            strategy = new FacebookStrategy(fbAuthConfig, this._handleAuthentication.bind(this));
            passport.use(strategy);
        }
        if (authConfig.google) {
            if (!authConfig.google.callbackURL) {
                authConfig.google.callbackURL = this.hostURL + '/' + this.authPath + '/google/callback';
            }
            strategy = new GoogleStrategy(authConfig.google, this._handleAuthentication.bind(this));
            passport.use(strategy);
        }
    }
    LHSessionMgr.prototype.register = function (app) {
        // Setup session options
        // TODO: research resave and saveUninitialized!
        app.use(session({
            resave: false,
            saveUninitialized: false,
            secret: 'lh-session-seed-wickedcoolspaghettimonstah'
        }));
        // Initialize Passport
        app.use(passport.initialize());
        // Use passport.session() middleware, to support
        // persistent signin sessions (recommended).
        app.use(passport.session());
        if (this.authConfig.facebook) {
            this._registerRoutes(app, 'facebook');
        }
        if (this.authConfig.google) {
            this._registerRoutes(app, 'google');
        }
    };
    LHSessionMgr.prototype.renderSignin = function () {
        var html = this.signinTmpl({
            appName: this.appName,
            klass: this.klass,
            signinFacebook: this.authConfig.facebook ? this._signinURL('facebook') : '',
            signinGoogle: this.authConfig.google ? this._signinURL('google') : ''
        });
        return html;
    };
    LHSessionMgr.prototype.isAuthorized = function (req, res, next) {
        if (req.isAuthenticated()) {
            console.log("Request is authenticated");
            return next();
        }
        console.log("Request is NOT authenticated");
        res.redirect(this.failurePath);
    };
    // 
    // Private methods
    // 
    LHSessionMgr.prototype._registerRoutes = function (app, provider) {
        // GET /<authPath>/<provider>
        //   Use passport.authenticate() as route middleware to authenticate the
        //   request.  The first step in authentication will involve
        //   redirecting the user to the provider.  After authorization, the provider will
        //   redirect the user back to this application at /<authPath>/<provider>/callback
        //   (Note, this callback must be one of the valid callbacks for this Lighthouse
        //   Identity Server in the provider's application configuration security settings).
        app.get(this._signinURL(provider), function (req, res) {
            // Special case for Google
            if (provider === 'google') {
                console.log("Google signin for", provider);
                passport.authenticate(provider, { scope: ['openid email profile'] });
            }
            else {
                console.log("In other signin for", provider);
                passport.authenticate(provider);
            }
        }, function (req, res) {
            console.log("In signin redirect !?");
            // The request will be redirected to the provider for authentication, 
            // so this function will not be called.
        });
        // GET /<authPath>/<provider>/callback
        //   Use passport.authenticate() as route middleware to authenticate the
        //   request.  If authentication fails, the user will be redirected back to the
        //   sign in page.  Otherwise, the primary route function function will be called,
        //   which, in this example, will redirect the user to the home page.
        app.get(this._callbackURL(provider), passport.authenticate(provider, { failureRedirect: this.failurePath }), function (req, res) {
            console.log("Successful authentication!");
            res.redirect(this.successPath);
        });
    };
    ;
    LHSessionMgr.prototype._handleAuthentication = function (accessToken, refreshToken, profile, done) {
        // asynchronous verification, for effect...
        process.nextTick(function () {
            console.log("Successfully Authenticated", profile);
            // To keep the example simple, the user's profile is returned to
            // represent the logged-in user.  In a typical application, you would want
            // to associate the account with a user record in your database,
            // and return that user instead.
            return done(null, profile);
        });
    };
    LHSessionMgr.prototype._signinURL = function (provider) {
        return this.authPath + '/' + provider;
    };
    LHSessionMgr.prototype._callbackURL = function (provider) {
        return this.authPath + '/' + provider + '/callback';
    };
    return LHSessionMgr;
})();
exports.LHSessionMgr = LHSessionMgr;
//# sourceMappingURL=index.js.map