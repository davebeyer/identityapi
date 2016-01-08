/// <reference path="./typings/tsd.d.ts" />
var FIRST_USERID = 100;
var DB_NAME = 'UserIdentities';
var STATE_DATA_DFLT = { rememberMe: false };
var USER_MATCH_TYPES = ['pending', 'rejected', 'failed', 'postponed'];
var moment = require('moment');
var passport = require('passport');
var session = require('express-session');
var SessionStore = require('express-session-rethinkdb')(session);
var FacebookStrategy = require('passport-facebook').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
//
// Lighthouse Session Manager
//
var LHSessionMgr = (function () {
    function LHSessionMgr(appAbbrev, hostURL, authConfig, options) {
        var _this = this;
        var options = options || {};
        this.appAbbrev = appAbbrev;
        this.hostURL = hostURL;
        this.authConfig = authConfig;
        this.authPath = options.authPath || "/auth";
        this.successPath = options.successPath || '/';
        this.signinPath = options.signinPath || this.authPath + '/signin';
        this.mergePath = options.mergePath || this.authPath + '/merge';
        this.dbHost = options.dbHost || 'localhost';
        this.dbPort = options.dbPort || 28035;
        this.secret = options.secret || 'lh-session-dflt-secret-hairyflump';
        // Open rethinkdb with connection pool, and set default database (works
        // even if UserIdentities doesn't yet exist)
        this.r = require('rethinkdbdash')({
            servers: [{ host: this.dbHost, port: this.dbPort }],
            db: DB_NAME
        });
        if (options.initDatabase) {
            this._initDB();
        }
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
            // Pass request object as first argument to callback
            authConfig.facebook.passReqToCallback = true;
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
            // Pass request object as first argument to callback
            authConfig.google.passReqToCallback = true;
            strategy = new GoogleStrategy(authConfig.google, this._handleAuthentication.bind(this));
            passport.use(strategy);
        }
    }
    LHSessionMgr.prototype.register = function (app) {
        var _this = this;
        //
        // Create session store manager
        // See: https://github.com/armenfilipetyan/express-session-rethinkdb
        //
        var sessionStore = new SessionStore({
            connectOptions: {
                servers: [{ host: this.dbHost, port: this.dbPort }],
                db: DB_NAME
            },
            table: 'sessions',
            sessionTimeout: 3 * 24 * 60 * 60 * 1000 // 3 days
        });
        //
        // Setup session options
        // See: https://www.npmjs.com/package/express-session
        //
        app.use(session({
            // Ensure the cookie name is different for each application
            // (called 'key' in prior versions of express-session)
            name: 'lh-sid.' + this.appAbbrev,
            // Use 'sessions' table in RethinkDB for session store 
            // (created above)
            store: sessionStore,
            // Force resaves to session store when there are no changes, 
            // since the rethinkdb session store doesn't support the "touch" method.
            resave: true,
            // Don't save new sessions that haven't been modified 
            // (not yet initialized)
            saveUninitialized: false,
            // Required option, used to sign the session ID cookie
            // (BTW, separately initializing session-cookie middleware 
            // is no longer needed/recommended as cookies are now handled
            // in the session middleware.)
            secret: this.secret,
            // 
            // Following are for securing cookies, see:
            // https://stormpath.com/blog/everything-you-ever-wanted-to-know-about-node-dot-js-sessions/
            // 
            cookie: {
                // Prevent Javascript code from accessing cookies
                httpOnly: true,
                // Ensure cookies are only used over https
                // secure: true,
                // Should cookies be deleted when closing the browser?
                // Instead, could implement per-session, e.g., see:
                // http://stackoverflow.com/questions/4371178/session-only-cookie-for-express-js
                // By default, expire sessions when the browser is closed.  If "Remember Me" 
                // is checked, then maxAge will be set elsewhere on a session-specific basis.  
                // res.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;   // 30 days
                maxAge: null
            }
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
        //
        // Register special merge routes
        //
        app.get(this.authPath + '/merge/reject', function (req, res, next) {
            // Move all pending to rejected
            if (_this._moveUserMatches(req.user, 'pending', 'rejected')) {
                _this.r.table('users').get(req.user.id).update({
                    matches: req.user.matches
                }).run().then(function () {
                    res.redirect(_this.successPath);
                }).catch(function (err) {
                    console.error("LHSessionMgr: failed rejecting user matches with error: ", err);
                    res.redirect(_this.successPath);
                });
            }
            else {
                res.redirect(_this.successPath);
            }
            ;
        });
        app.get(this.authPath + '/merge/postpone', function (req, res, next) {
            // Move all pending to rejected
            if (_this._moveUserMatches(req.user, 'pending', 'postponed')) {
                var now = moment(new Date());
                now.add(1, 'day'); // tomorrow
                req.user.matches['postponedUntil'] = now.toDate();
                _this.r.table('users').get(req.user.id).update({
                    matches: req.user.matches
                }).run().then(function () {
                    res.redirect(_this.successPath);
                }).catch(function (err) {
                    console.error("LHSessionMgr: failed rejecting user matches with error: ", err);
                    res.redirect(_this.successPath);
                });
            }
            else {
                res.redirect(_this.successPath);
            }
            ;
        });
    };
    LHSessionMgr.prototype.signinOptions = function () {
        var providers = [];
        if (this.authConfig.facebook) {
            providers.push({ provider: 'facebook',
                signinUrl: this._signinURL('facebook') });
        }
        if (this.authConfig.google) {
            providers.push({ provider: 'google',
                signinUrl: this._signinURL('google') });
        }
        return { providers: providers };
    };
    LHSessionMgr.prototype.mergeOptions = function (req) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            if (!req || !req.user || !req.user.matches) {
                resolve(null);
                return;
            }
            var options = {
                rejectUrl: _this.authPath + '/merge/reject',
                postponeUrl: _this.authPath + '/merge/postpone',
                matches: []
            };
            _this._getUserMatchIds(req.user).then(function (pendingUserIds) {
                if (pendingUserIds.length <= 0) {
                    return (null);
                }
                var pList = [];
                // TODO: could consider making this more efficient, but at least for now, 
                //        get one user at a time (typical case is there will only be a 
                //        single user to merge)
                for (var i = 0; i < pendingUserIds.length; i++) {
                    pList.push(_this.getUser(pendingUserIds[i]));
                }
                return Promise.all(pList);
            }).then(function (pendings) {
                if (!pendings) {
                    resolve(options);
                    return;
                }
                var pendingsDict = {};
                for (var i = 0; i < pendings.length; i++) {
                    var providerInfo = pendings[i].providerInfo ? pendings[i].providerInfo : [];
                    for (var j = 0; j < providerInfo.length; j++) {
                        var infoId = providerInfo[j].id;
                        if (!(infoId in pendingsDict)) {
                            providerInfo[j]['mergeUrl'] = _this.authPath + '/merge/' + providerInfo[j].provider + '?uid=' + providerInfo[j].userId;
                            options.matches.push(providerInfo[j]);
                            pendingsDict[infoId] = true;
                        }
                    }
                }
                resolve(options);
            }).catch(function (err) {
                console.error("LHSessionMgr:mergeOptions - failed to get matching users with error: ", err);
                resolve(options); // return with no match options (to allow user to skip/reject)
            });
        });
    };
    LHSessionMgr.prototype.signout = function (req) {
        req.logout();
    };
    LHSessionMgr.prototype.currentUser = function (req) {
        if (req.isAuthenticated()) {
            // TODO: is this the proper way?
            return req['user'];
        }
        return null;
    };
    LHSessionMgr.prototype.pendingUserMatchIds = function (req) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            if (!req) {
                resolve([]);
                return;
            }
            _this._getUserMatchIds(req.user).then(function (matchedUserIds) {
                resolve(matchedUserIds);
            });
        });
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
                    if (authInfo && authInfo.length > 0) {
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
            console.log("initDB: About to create sessions table");
            return _r.tableCreate('sessions').run();
        }).finally(function () {
            console.log("initDB: About to create users table");
            return _r.tableCreate('users').run();
        }).finally(function () {
            console.log("initDB: About to insert dummy user");
            return _r.table('users').insert({
                id: 99,
                created: new Date(),
                active: true
            });
        }).finally(function () {
            console.log("initDB: About to create authState table");
            return _r.tableCreate('authState').run();
        }).finally(function () {
            console.log("initDB: About to create authProviders table");
            return _r.tableCreate('authProviders').run();
        }).finally(function () {
            console.log("initDB: About to insert dummy authProvider entry");
            return _r.table('authProviders').insert({
                id: 'lh:99',
                created: new Date(),
                userId: 99,
                provider: 'lh',
                providerId: 99,
                username: 'dummy@example.com',
                passwordHash: null,
                lastSignin: null,
                emails: [{ value: 'dummy1@example.com' },
                    { value: 'DUMMY2@example.com' }],
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
            return _r.table('authProviders').indexCreate('emailIndex', 
            // Use .map() to translate the 'emails' array
            _r.row('emails').map(function (email) {
                // Get nested field using function call
                // 'email' here.  Then, 
                // need to use expr() to convert to an object that 
                // ReQL commands can operate on
                return _r.expr(email('value')).downcase();
            }), { multi: true }).run();
        }).error(function (err) {
            console.log("initDB: Error creating emailIndex: ", err);
        }).finally(function () {
            console.log("initDB: About to wait for emailIndex");
            return _r.table('authProviders').indexWait('emailIndex').run();
        }).finally(function () {
            console.log("initDB: Done!");
        });
    };
    LHSessionMgr.prototype._registerRoutes = function (app, provider) {
        var _this = this;
        // GET /<authPath>/<provider>
        //   Use passport.authenticate() as route middleware to authenticate the
        //   request.  The first step in authentication will involve
        //   redirecting the user to the provider.  After authorization, the provider will
        //   redirect the user back to this application at /<authPath>/<provider>/callback
        //   (Note, this callback must be one of the valid callbacks for this Lighthouse
        //   Identity Server in the provider's application configuration security settings).
        app.get(_this._signinURL(provider), function (req, res, next) {
            var rememberMe = req.query && req.query.remember ? parseInt(req.query.remember) : 0;
            console.log("signin for " + provider + ", authenticating with remember me = " + rememberMe);
            var stateData = {
                provider: provider,
                type: 'signin',
                rememberMe: rememberMe == 1 ? true : false
            };
            _this._providerSignin(stateData, req, res, next);
        }, function (req, res) {
            console.log("signin for " + provider + ", in redirect !?");
            // The request will be redirected to the provider for authentication, 
            // so this function will not be called.
        });
        app.get(_this._mergeURL(provider), function (req, res, next) {
            var srcUserId = req.query && req.query.uid ? parseInt(req.query.uid) : null;
            console.log("/auth/merge/" + provider + ", authenticating for srcUserId = " + srcUserId);
            var stateData = {
                provider: provider,
                type: 'merge',
                srcUserId: srcUserId,
                rememberMe: false
            };
            _this._providerSignin(stateData, req, res, next);
        }, function (req, res) {
            console.log("/auth/merge/" + provider + ", in redirect !?");
            // The request will be redirected to the provider for authentication, 
            // so this function will not be called.
        });
        // GET /<authPath>/<provider>/callback
        //   Use passport.authenticate() as route middleware to authenticate the
        //   request.  If authentication fails, the user will be redirected back to the
        //   sign in page.  Otherwise, the primary route function function will be called,
        //   which, in this example, will redirect the user to the home page.
        var callbackAuthFn = passport.authenticate(provider, { failureRedirect: _this.signinPath });
        app.get(_this._callbackURL(provider), function (req, res, next) {
            console.log("Authenticating callback for " + provider);
            return callbackAuthFn(req, res, next);
        }, function (req, res) {
            console.log("Successful authentication!, redirecting", _this.successPath);
            res.redirect(_this.successPath);
        });
    };
    ;
    LHSessionMgr.prototype._providerSignin = function (stateData, req, res, next) {
        var provider = stateData.provider;
        this._saveAuthState(stateData, function (stateId) {
            var authenticateFn;
            if (provider === 'google') {
                // Special case for Google
                authenticateFn = passport.authenticate(provider, {
                    scope: ['openid email profile'],
                    state: stateId
                });
            }
            else {
                // All others
                authenticateFn = passport.authenticate(provider, {
                    scope: ['email'],
                    state: stateId
                });
            }
            return authenticateFn(req, res, next);
        });
    };
    LHSessionMgr.prototype._saveAuthState = function (data, done) {
        var statePkg = {
            // id   : <random UUID auto-assigned>
            data: data,
            created: new Date(),
            used: null
        };
        this.r.table('authState').insert(statePkg).run(function (err, res) {
            if (err) {
                console.error("Inserting authState received error: " + err);
            }
            if (res && res.generated_keys && res.generated_keys.length > 0) {
                done(res.generated_keys[0]);
            }
            else {
                done('');
            }
        });
    };
    LHSessionMgr.prototype._getAuthState = function (stateId, done) {
        var _this = this;
        if (!stateId || stateId.length <= 0) {
            done(STATE_DATA_DFLT);
            return;
        }
        _this.r.table('authState').get(stateId).run(function (err, statePkg) {
            if (err || !statePkg) {
                console.error("getAuthState failed with error: " + err);
                done(null);
                return;
            }
            if (statePkg.used != null) {
                console.error("Attempt to reuse an authState document, stateId " + stateId);
                done(null);
            }
            else {
                // Just do update in parallel (could check for update conflict, 
                // but probably overkill)
                _this.r.table('authState').get(stateId).update({ used: new Date() }).run();
                done(statePkg.data);
            }
        });
    };
    // Handle authentication callback.
    //
    // request object passed as first parameter due to passReqToCallback setting above
    // This is registered with the Facebook and GoogleStrategy objects, and is called
    // during passport's handling of the authentication callback that the provider redirects
    // the browser to.
    LHSessionMgr.prototype._handleAuthentication = function (req, accessToken, refreshToken, authProfile, done) {
        var _this = this;
        var _r = this.r;
        var stateId = req.query ? req.query.state : null;
        this._getAuthState(stateId, function (stateData) {
            if (!stateData) {
                stateData = {};
            }
            if (stateData.type == 'signin' && stateData.rememberMe) {
                // Remember me flag
                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 1 month
            }
            process.nextTick(function () {
                if (stateData.type == 'merge') {
                    //
                    // Handle merge
                    //
                    var dstUserId = req.user.id;
                    var srcUserId = stateData.srcUserId;
                    var providerIdStr = _this._providerIdStr(authProfile.provider, authProfile.id);
                    console.log("Successful signin to " + authProfile.displayName + " using " + authProfile.provider + " for merge of " + srcUserId + " into " + dstUserId);
                    _r.table('authProviders').get(providerIdStr).run().then(function (match) {
                        if (match) {
                            // Assemble the full user document
                            return _this.getUser(match.userId);
                        }
                        else {
                            return null;
                        }
                    }).then(function (user) {
                        if (!user) {
                            console.error("Unable to get source user " + srcUserId + " for merge, no user for provider id " + providerIdStr);
                            return null;
                        }
                        if (user.id != srcUserId) {
                            console.error("Unable to get source user " + srcUserId + " for merge, user just authenticated with " + providerIdStr + " which has userId " + user.id);
                            return null;
                        }
                        // We have the correct destination user!   So, now change the original 
                        // user info to merge into this destination user.
                        return _this._mergeUsers(user, req.user);
                    }).then(function (user) {
                        // resolve with new user (should be set to the destination user,
                        // which will be the current user that we're signed in as (so user
                        // doesn't need to resign in), and will be modified with the new
                        // provider Info
                        done(null, user);
                    }).catch(function (err) {
                        if (err) {
                            console.error("Merge failed with error", err);
                        }
                        // Just leave current user with the original user, and user.matches as is
                        // (so user will be presented with merging choices again)
                        done(null, req.user);
                    });
                }
                else {
                    //
                    // Handle signin
                    //
                    // Special case for google (passport-google plugin is apparently missing this)
                    if (!authProfile.profileUrl && authProfile._json.url) {
                        authProfile.profileUrl = authProfile._json.url;
                    }
                    console.log("Successfully authenticated " + authProfile.displayName + " using " + authProfile.provider + " with remember me " + (stateData ? stateData.rememberMe : 0));
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
                            return null;
                        }
                    }).then(function (user) {
                        if (user) {
                            // Update lastSignin 
                            _r.table('authProviders').get(providerIdStr).update({ lastSignin: new Date() }).run();
                            // but no need to wait for this one (not a big deal if there's a race
                            // condition for this lastSignin date property)
                            return user;
                        }
                        else {
                            // Unable to lookup an existing user, so create a new one
                            return _this._createUser(authProfile);
                        }
                    }).then(function (user) {
                        return done(null, user);
                    }).error(function (err) {
                        console.error("Getting user returned error", err);
                        return done(null, null);
                    });
                }
            });
        });
    };
    // Assumes that providerInfo list has been attached to the 
    // user document at this point
    LHSessionMgr.prototype._attachUserMatches = function (user) {
        var _this = this;
        var _r = this.r;
        var i, j;
        return new Promise(function (resolve, reject) {
            var emails = [];
            var email;
            for (i = 0; i < user.providerInfo.length; i++) {
                if (user.providerInfo[i].emails) {
                    for (j = 0; j < user.providerInfo[i].emails.length; j++) {
                        var email = user.providerInfo[i].emails[j].value;
                        if (!_this._listContains(emails, email, { caseInsensitive: true }))
                            emails.push(email.toLowerCase());
                    }
                }
            }
            // Search for all authProvider documents which match any of the emails in this authProfile
            _r.table('authProviders').getAll(_r.args(emails), { index: 'emailIndex' }).run().then(function (matches) {
                var matchedUserIds = [];
                if (matches) {
                    for (j = 0; j < matches.length; j++) {
                        if (matches[j].userId != user.id) {
                            matchedUserIds.push(matches[j].userId);
                        }
                    }
                }
                var matchId;
                var changeFlag = false;
                if (!user.matches) {
                    user.matches = {};
                }
                for (j = 0; j < matchedUserIds.length; j++) {
                    matchId = matchedUserIds[j];
                    if (_this._getUserMatchTypesForId(user, matchId).length == 0) {
                        changeFlag = _this._addUserMatch(user, matchId, 'pending');
                    }
                }
                if (!changeFlag) {
                    resolve(user); // unchanged
                    return;
                }
                _this.r.table('users').get(user.id).update({ matches: user.matches }).run(function (err, res) {
                    if (err) {
                        console.error("_attachUserMatches: received error when updating user with matches: ", user.id, user);
                    }
                    resolve(user); // changes set above (should be same as that stored in DB, assuming no error
                    return;
                });
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
                    created: new Date(),
                    active: true
                };
                return _r.table('users').insert(user).run();
            }).then(function (res) {
                return _this._createAuthProviderForUser(user, info);
            }).then(function (user) {
                // In this case of creating a new user, check to see whether 
                // there are other potential matches that should be presented
                // to the user for possible merging (and if so, add those to the 
                // user document)
                return _this._attachUserMatches(user); // has providerInfo attached
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
            var created = new Date();
            providerInfo = {
                id: _this._providerIdStr(info.provider, info.id),
                created: created,
                userId: user.id,
                provider: info.provider,
                providerId: info.id,
                username: info.username,
                passwordHash: null,
                lastSignin: created,
                emails: info.emails,
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
                var compareList = user.emails.map(function (emailRow) { return emailRow.value; });
                for (j = 0; j < info.emails.length; j++) {
                    if (!this._listContains(compareList, info.emails[j].value, { caseInsensitive: true })) {
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
    LHSessionMgr.prototype._mergeUsers = function (srcUser, dstUser) {
        var _this = this;
        var _r = this.r;
        //
        // BTW, don't switch src/dst users, according to which is oldest for instance.
        // Just merge into the dstUser, which is the one the user is currently signed in
        // so that the user doesn't need to re-signin after this is done
        //
        return new Promise(function (resolve, reject) {
            var pList = [];
            var newProm;
            var i;
            // Update any/all src user's authProvider docs to point to new, 
            // destination user and add these to the new dst user record
            for (i = 0; i < srcUser.providerInfo.length; i++) {
                var info = srcUser.providerInfo[i];
                newProm = _r.table('authProviders').get(info.id).update({ userId: dstUser.id }).run();
                pList.push(newProm);
                if (!dstUser.providerInfo) {
                    dstUser.providerInfo = [];
                }
                info.userId = dstUser.id;
                dstUser.providerInfo.push(info);
            }
            // Consolidate provider info in user object
            _this._consolidateProviderInfo(dstUser);
            // Update srcUser users document to be inactive 
            // and remove this pending from matches, if there
            _this._removeUserMatch(srcUser, dstUser.id);
            newProm = _r.table('users').get(srcUser.id).update({
                active: false,
                merged: new Date(),
                mergedInto: dstUser.id,
                matches: srcUser.matches
            }).run();
            pList.push(newProm);
            // Update dstUser users document to remove this pending, if there
            if (_this._removeUserMatch(dstUser, srcUser.id)) {
                newProm = _r.table('users').get(dstUser.id).update({
                    matches: dstUser.matches
                }).run();
                pList.push(newProm);
            }
            // Wait for all of above to complete
            Promise.all(pList).then(function (results) {
                console.log("Finished user merge of " + srcUser.id + " into  " + dstUser.id);
                resolve(dstUser);
            }).catch(function (err) {
                console.error("User merge failed trying to merge " + srcUser.id + " into " + dstUser.id);
                resolve(dstUser);
            });
        });
    };
    //
    // User match convenience methods
    //
    LHSessionMgr.prototype._addUserMatch = function (user, userId, matchType) {
        if (USER_MATCH_TYPES.indexOf(matchType) == -1) {
            console.error("LHSessionMgr:_addUserMatch - invalid match type: ", matchType);
            return false;
        }
        if (!user.matches) {
            user.matches = {};
        }
        if (this._listContains(user.matches[matchType], userId)) {
            return false; // nothing to do
        }
        else {
            if (!user.matches[matchType]) {
                user.matches[matchType] = [];
            }
            user.matches[matchType].push(userId);
            return true;
        }
    };
    LHSessionMgr.prototype._moveUserMatches = function (user, fromType, toType) {
        if (USER_MATCH_TYPES.indexOf(fromType) == -1) {
            console.error("LHSessionMgr:_moveUserMatches - invalid from match type: ", fromType);
            return false;
        }
        if (USER_MATCH_TYPES.indexOf(toType) == -1) {
            console.error("LHSessionMgr:_moveUserMatches - invalid to match type: ", toType);
            return false;
        }
        if (!user.matches) {
            user.matches = {};
        }
        if (!user.matches[fromType] || user.matches[fromType].length <= 0) {
            return false; // nothing to do
        }
        else {
            if (!user.matches[toType]) {
                user.matches[toType] = [];
            }
            user.matches[toType] = user.matches[toType].concat(user.matches[fromType]);
            user.matches[fromType] = [];
            return true;
        }
    };
    LHSessionMgr.prototype._getUserMatchTypesForId = function (user, userId) {
        if (!user || !user.matches) {
            return [];
        }
        var res = [];
        if (this._listContains(user.matches.pending, userId)) {
            res.push('pending');
        }
        if (this._listContains(user.matches.rejected, userId)) {
            res.push('rejected');
        }
        if (this._listContains(user.matches.postponed, userId)) {
            res.push('postponed');
        }
        if (this._listContains(user.matches.failed, userId)) {
            res.push('failed');
        }
        return res;
    };
    LHSessionMgr.prototype._getUserMatchIds = function (user, options) {
        var _this = this;
        if (!options) {
            options = {};
        }
        return new Promise(function (resolve, reject) {
            if (!user || !user.matches) {
                resolve([]);
                return;
            }
            // Update pendings with postponed if appropriate
            var changeFlag = false;
            if (!options.ignorePostponed) {
                if (user.matches['postponed'] && user.matches['postponed'].length) {
                    if (!user.matches['postponedUntil'] ||
                        (user.matches['postponedUntil'] <= new Date())) {
                        if (!user.matches['pending']) {
                            user.matches['pending'] = [];
                        }
                        user.matches['pending'] = user.matches['pending'].concat(user.matches['postponed']);
                        user.matches['postponed'] = [];
                        user.matches['postponedUntil'] = [];
                        changeFlag = true;
                    }
                }
            }
            var matchIds = [];
            // Get pendings
            if (user.matches['pending']) {
                matchIds = matchIds.concat(user.matches['pending']);
            }
            // Get rejected, if appropriate
            if (options.includeAll || options.includeRejected) {
                if (user.matches['rejected']) {
                    matchIds = matchIds.concat(user.matches['rejected']);
                }
            }
            // Get failed, if appropriate
            if (options.includeAll || options.includeFailed) {
                if (user.matches['failed']) {
                    matchIds = matchIds.concat(user.matches['failed']);
                }
            }
            if (!changeFlag) {
                resolve(matchIds);
            }
            else {
                _this.r.table('users').get(user.id).update({ matches: user.matches }).run(function (err, res) {
                    if (err) {
                        console.error("LHSessionMgr:getUserMatchIds: received error when updating user with matches: ", user.id, user);
                    }
                    resolve(matchIds);
                });
            }
        });
    };
    LHSessionMgr.prototype._removeUserMatch = function (user, otherUserId) {
        var changeFlag = false;
        changeFlag = changeFlag || this._removeUserMatchFrom(user, otherUserId, 'pending');
        changeFlag = changeFlag || this._removeUserMatchFrom(user, otherUserId, 'rejected');
        changeFlag = changeFlag || this._removeUserMatchFrom(user, otherUserId, 'failed');
        changeFlag = changeFlag || this._removeUserMatchFrom(user, otherUserId, 'postponed');
        return changeFlag;
    };
    LHSessionMgr.prototype._removeUserMatchFrom = function (user, otherUserId, matchType) {
        if (USER_MATCH_TYPES.indexOf(matchType) == -1) {
            console.error("LHSessionMgr:_removeUserMatchFrom - invalid match type: ", matchType);
            return false;
        }
        if (!user || !user.matches || !user.matches[matchType]) {
            return false;
        }
        var i = user.matches[matchType].indexOf(otherUserId);
        if (i > -1) {
            // Remove this element
            user.matches[matchType].splice(i, 1);
            if (user.matches[matchType].length == 0) {
                // could optionally remove this key when saving to DB
                user.matches[matchType] = [];
            }
            return true;
        }
        else {
            return false;
        }
    };
    //
    // Miscellaneous convenience methods
    //
    LHSessionMgr.prototype._listContains = function (itemList, item, options) {
        if (!itemList) {
            return false;
        }
        if (options.caseInsensitive) {
            item = item.toLowerCase();
        }
        for (var i = 0; i < itemList.length; i++) {
            if (options.caseInsensitive) {
                if (itemList[i].toLowerCase() == item) {
                    return true;
                }
            }
            else if (itemList[i] == item) {
                return true;
            }
        }
        return false;
    };
    LHSessionMgr.prototype._signinURL = function (provider) {
        return this.authPath + '/' + provider;
    };
    LHSessionMgr.prototype._mergeURL = function (provider) {
        return this.authPath + '/merge/' + provider;
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