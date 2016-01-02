/// <reference path="./typings/tsd.d.ts" />
var swig_1 = require('swig');
var FIRST_USERID = 100;
var passport = require('passport');
var session = require('express-session');
var FacebookStrategy = require('passport-facebook').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var path = require('path');
//
// Lighthouse Session Manager
//
var LHSessionMgr = (function () {
    function LHSessionMgr(appName, hostURL, authConfig, options) {
        var _this = this;
        var options = options || {};
        this.appName = appName;
        this.hostURL = hostURL;
        this.authConfig = authConfig;
        this.klass = options.klass || "lh-identity";
        this.authPath = options.authPath || "/auth";
        this.successPath = options.successPath || '/';
        this.failurePath = options.failurePath || this.authPath + '/signin';
        this.dbHost = options.dbHost || 'localhost';
        this.dbPort = options.dbPort || 28035;
        // Open rethinkdb with connection pool, and set default database (works
        // even if UserIdentities doesn't yet exist)
        this.r = require('rethinkdbdash')({
            servers: [{ host: this.dbHost, port: this.dbPort }],
            db: 'UserIdentities'
        });
        if (options.initDatabase) {
            this._initDB();
        }
        this.signinTmpl = swig_1.compileFile(path.resolve(__dirname, 'signin.tmpl.html'));
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
            // return the user's LH id given the LH user profile info
            done(null, user.id);
        });
        passport.deserializeUser(function (userId, done) {
            // return the user's LH profile info given the userId
            _this.getUser(userId).then(function (user) {
                done(null, user);
            }).catch(function (err) {
                console.error("desializeuser: Unable to get user", userId);
                done(null, null);
            });
        });
        var strategy;
        if (authConfig.facebook) {
            if (!authConfig.facebook.callbackURL) {
                authConfig.facebook.callbackURL = this.hostURL + this.authPath + '/facebook/callback';
            }
            // For Facebook, need to specify profileFields to fetch.  First, create copy
            var fbAuthConfig = (JSON.parse(JSON.stringify(authConfig.facebook)));
            // Then add profileFields
            fbAuthConfig.profileFields = ["id", "name", "displayName", "photos", "profileUrl", "email", "gender"];
            strategy = new FacebookStrategy(fbAuthConfig, this._handleAuthentication.bind(this));
            passport.use(strategy);
        }
        if (authConfig.google) {
            if (!authConfig.google.callbackURL) {
                authConfig.google.callbackURL = this.hostURL + this.authPath + '/google/callback';
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
    LHSessionMgr.prototype.currentUserId = function (req) {
        if (req.isAuthenticated()) {
            // TODO: is this the proper way?
            return req['user'].id;
        }
        return null;
    };
    LHSessionMgr.prototype.getUser = function (userId) {
        var _this = this;
        var _r = this.r;
        var user;
        return new Promise(function (resolve, reject) {
            _r.table('users').get(userId).run().then(function (userMatch) {
                user = userMatch;
                return _r.table('authProviders').getAll(userId, { index: "userIdIndex" }).run();
            }).then(function (authInfo) {
                var msg;
                if (!user || !authInfo || authInfo.length <= 0) {
                    if (user) {
                        msg = "user found but no authProviders for userId: " + userId;
                    }
                    if (authInfo) {
                        msg = "authProviders found but no user for userId: " + userId;
                    }
                    console.error(msg);
                    reject(msg);
                    return;
                }
                user.providerInfo = authInfo;
                // Consolidate providerInfo into user object
                _this._consolidateProviderInfo(user);
                resolve(user);
            }).catch(function (err) {
                var msg = "getUser: failed with error: " + err;
                reject(Error(msg));
            });
        });
    };
    // 
    // Private methods
    // 
    LHSessionMgr.prototype._initDB = function () {
        var _r = this.r;
        console.log("initDB: About to create UserIdentities");
        _r.dbCreate("UserIdentities").run().finally(function () {
            console.log("initDB: About to create globals table");
            return _r.tableCreate('globals').run();
        }).finally(function () {
            console.log("initDB: About to insert userCount into globals table");
            return _r.table('globals').insert({
                id: 'userCount',
                value: 0
            }).run();
        }).finally(function () {
            console.log("initDB: About to create users table");
            return _r.tableCreate('users').run();
        }).finally(function () {
            console.log("initDB: About to insert dummy user");
            return _r.table('users').insert({
                id: 99,
                created: new Date(),
            });
        }).finally(function () {
            console.log("initDB: About to create authProviders table");
            return _r.tableCreate('authProviders').run();
        }).finally(function () {
            console.log("initDB: About to insert dummy authProvider entry");
            return _r.table('authProviders').insert({
                id: 'lh:99',
                userId: 99,
                provider: 'lh',
                providerId: 99,
                username: 'dummy@example.com',
                passwordHash: null,
                lastSignin: null,
                emails: ['dummy1@example.com', 'DUMMY2@example.com'],
                displayName: 'Dummy User',
                name: {
                    familyName: 'User',
                    givenName: 'Dummy',
                    middleName: null
                },
                gender: 'other',
                photos: [],
                profileUrl: ''
            }).run();
        }).finally(function () {
            console.log("initDB: About to create userIdIndex");
            return _r.table('authProviders').indexCreate('userIdIndex', _r.row('userId')).run();
        }).finally(function () {
            console.log("initDB: About to wait for userIdIndex");
            return _r.table('authProviders').indexWait('userIdIndex').run();
        }).finally(function () {
            console.log("initDB: About to create emailIndex");
            return _r.table('authProviders').indexCreate('emailIndex', _r.row('emails').map(function (email) {
                // need to use expr() to convert to an object that 
                // ReQL commands can operate on
                return _r.expr(email).downcase();
            }), { multi: true }).run();
        }).finally(function () {
            console.log("initDB: About to wait for emailIndex");
            return _r.table('authProviders').indexWait('emailIndex').run();
        }).finally(function () {
            console.log("initDB: Done!");
        });
    };
    LHSessionMgr.prototype._registerRoutes = function (app, provider) {
        var self = this;
        // GET /<authPath>/<provider>
        //   Use passport.authenticate() as route middleware to authenticate the
        //   request.  The first step in authentication will involve
        //   redirecting the user to the provider.  After authorization, the provider will
        //   redirect the user back to this application at /<authPath>/<provider>/callback
        //   (Note, this callback must be one of the valid callbacks for this Lighthouse
        //   Identity Server in the provider's application configuration security settings).
        var authenticateFn;
        if (provider === 'google') {
            // Special case for Google
            authenticateFn = passport.authenticate(provider, { scope: ['openid email profile'] });
        }
        else {
            // authenticateFn = passport.authenticate(provider);
            authenticateFn = passport.authenticate(provider, { scope: ['email'] });
        }
        app.get(self._signinURL(provider), authenticateFn, function (req, res) {
            console.log("In signin redirect !?");
            // The request will be redirected to the provider for authentication, 
            // so this function will not be called.
        });
        // GET /<authPath>/<provider>/callback
        //   Use passport.authenticate() as route middleware to authenticate the
        //   request.  If authentication fails, the user will be redirected back to the
        //   sign in page.  Otherwise, the primary route function function will be called,
        //   which, in this example, will redirect the user to the home page.
        var callbackAuthFn = passport.authenticate(provider, { failureRedirect: self.failurePath });
        app.get(self._callbackURL(provider), function (req, res, next) {
            console.log("Authenticating callback");
            return callbackAuthFn(req, res, next);
        }, function (req, res) {
            console.log("Successful authentication!, redirecting", self.successPath);
            res.redirect(self.successPath);
        });
    };
    ;
    LHSessionMgr.prototype._handleAuthentication = function (accessToken, refreshToken, authProfile, done) {
        var _this = this;
        var _r = this.r;
        process.nextTick(function () {
            // Special case for google (passport-google plugin is apparently missing this)
            if (!authProfile.profileUrl && authProfile._json.url) {
                authProfile.profileUrl = authProfile._json.url;
            }
            console.log("Successfully Authenticated", authProfile);
            var providerIdStr = _this._providerIdStr(authProfile.provider, authProfile.id);
            //
            // First, check whether this user already has a listing from this provider
            //
            _r.table('authProviders').get(providerIdStr).run().then(function (match) {
                if (match) {
                    // Assemble the full user document
                    return _this.getUser(match.userId);
                }
                else {
                    // Look for a match for this user with another provider
                    return _this._seekUserMatch(authProfile);
                }
            }).then(function (user) {
                if (user) {
                    return done(null, user);
                }
                else {
                    // Unable to lookup or match to existing user, so create a new one
                    return _this._createUser(authProfile);
                }
            }).then(function (user) {
                return done(null, user);
            }).error(function (err) {
                console.error("Getting user returned error", err);
                return done(null, null);
            });
        });
    };
    LHSessionMgr.prototype._seekUserMatch = function (authProfile) {
        var _this = this;
        var _r = this.r;
        return new Promise(function (resolve, reject) {
            if (!authProfile.emails) {
                resolve(null); // no matches
                return;
            }
            var emails = [];
            for (var i = 0; i < authProfile.emails.length; i++) {
                emails.push(authProfile.emails[i]['value'].toLowerCase());
            }
            // Search for all authProvider documents which match any of the emails in this authProfile
            _r.table('authProviders').getAll(_r.args(emails), { index: 'emailIndex' }).run().then(function (matches) {
                if (!matches || matches.length <= 0) {
                    return null;
                }
                else {
                    // merge this user with the first match
                    // So first, get the user
                    return _this.getUser(matches[0].userId);
                }
            }).then(function (user) {
                if (user) {
                    // Then, create the new authProvider, and add to this user
                    return _this._createAuthProviderForUser(user, authProfile);
                }
            }).then(function (user) {
                // return
                resolve(user); // may be null (if none could be found originally)
            }).catch(function (err) {
                var msg = "_seekUserMatch: failed with error: " + err;
                console.error(err);
                reject(err);
            });
        });
    };
    LHSessionMgr.prototype._createUser = function (info) {
        var _this = this;
        var _r = this.r;
        var user = null;
        return new Promise(function (resolve, reject) {
            console.log("About to incremenet userCount");
            _r.table('globals').get('userCount').update({ value: _r.row('value').add(1) }, { returnChanges: true }).run().then(function (res) {
                if (!res || !res.changes || !res.changes[0].new_val) {
                    var msg = "_createUser: Unable to increment global user count: " + res;
                    console.error(msg);
                    reject(msg);
                    return;
                }
                console.log("About to create new user doc");
                user = {
                    id: FIRST_USERID + res.changes[0].new_val['value'],
                    created: new Date()
                };
                return _r.table('users').insert(user).run();
            }).then(function (res) {
                return _this._createAuthProviderForUser(user, info);
            }).then(function (user) {
                resolve(user);
            }).catch(function (err) {
                reject(Error("Unable to create new user, got error: " + err));
            });
        });
    };
    LHSessionMgr.prototype._createAuthProviderForUser = function (user, info) {
        var _this = this;
        var _r = this.r;
        var providerInfo = null;
        return new Promise(function (resolve, reject) {
            console.log("About to create new authProvider for user");
            var i;
            var emails = [];
            if (info.emails) {
                for (i = 0; i < info.emails.length; i++) {
                    emails.push(info.emails[i].value);
                }
            }
            var photos = [];
            if (info.photos) {
                for (i = 0; i < info.photos.length; i++) {
                    photos.push(info.photos[i].value);
                }
            }
            providerInfo = {
                id: _this._providerIdStr(info.provider, info.id),
                userId: user.id,
                provider: info.provider,
                providerId: info.id,
                username: info.username,
                passwordHash: null,
                lastSignin: new Date(),
                emails: emails,
                displayName: info.displayName,
                name: {
                    familyName: info.name.familyName,
                    givenName: info.name.givenName,
                    middleName: info.name.middleName
                },
                gender: info.gender,
                photos: info.photos,
                profileUrl: info.profileUrl
            };
            _r.table('authProviders').insert(providerInfo).run().then(function (res) {
                if (!user.providerInfo) {
                    user.providerInfo = [];
                }
                user.providerInfo.push(providerInfo);
                // Consolidate new providerInfo in user object
                _this._consolidateProviderInfo(user);
                resolve(user);
            }).error(function (err) {
                reject(Error("Unable to create new user, got error: " + err));
            });
        });
    };
    LHSessionMgr.prototype._consolidateProviderInfo = function (user) {
        if (!user.providerInfo) {
            return;
        }
        var info, i, j;
        for (i = 0; i < user.providerInfo.length; i++) {
            info = user.providerInfo[i];
            if (!user.lastSignin || user.lastSignin < info.lastSignIn) {
                user.lastSignin = info.lastSignin;
            }
            if (info.emails) {
                if (!user.emails) {
                    user.emails = [];
                }
                for (j = 0; j < info.emails.length; j++) {
                    if (!this._listContains(user.emails, info.emails[j], { caseInsensitive: true })) {
                        user.emails.push(info.emails[j]);
                    }
                }
            }
            if (!user.displayName) {
                user.displayName = info.displayName;
            }
            if (!user.name) {
                user.name = {};
            }
            if (!user.name.familyName) {
                user.name.familyName = info.name.familyName;
            }
            if (!user.name.givenName) {
                user.name.familyName = info.name.givenName;
            }
            if (!user.name.middleName) {
                user.name.familyName = info.name.middleName;
            }
            if (!user.gender) {
                user.gender = info.gender;
            }
            if (info.photos) {
                if (!user.photos) {
                    user.photos = [];
                }
                for (j = 0; j < info.photos.length; j++) {
                    user.photos.push(info.photos[j]);
                }
            }
        }
    };
    LHSessionMgr.prototype._listContains = function (destList, newStr, options) {
        if (options.caseInsensitive) {
            newStr = newStr.toLowerCase();
        }
        for (var i = 0; i < destList.length; i++) {
            if (options.caseInsensitive) {
                if (destList[i].toLowerCase() == newStr) {
                    return true;
                }
            }
        }
        return false;
    };
    LHSessionMgr.prototype._signinURL = function (provider) {
        return this.authPath + '/' + provider;
    };
    LHSessionMgr.prototype._callbackURL = function (provider) {
        return this.authPath + '/' + provider + '/callback';
    };
    LHSessionMgr.prototype._providerIdStr = function (provider, providerId) {
        return provider + ':' + providerId;
    };
    return LHSessionMgr;
})();
exports.LHSessionMgr = LHSessionMgr;
//# sourceMappingURL=index.js.map