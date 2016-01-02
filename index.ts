/// <reference path="./typings/tsd.d.ts" />
import {compileFile} from 'swig';

var passport         = require('passport');
var session          = require('express-session');
var FacebookStrategy = require('passport-facebook').Strategy;
var GoogleStrategy   = require('passport-google-oauth').OAuth2Strategy;

var path             = require('path');

//
// Passport session setup.
//   To support persistent signin sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete Facebook profile is serialized
//   and deserialized.
//

passport.serializeUser(function(user, done) {
    // TODO: return the user's LH id given the LH user profile info
    // E.g., done(null, user.id)
    done(null, user);
});

passport.deserializeUser(function(userObj, done) {
    // TODO: return the user's LH profile info given the userId
    // E.g., DB.GetUser(userId, function(user) { done(null, userInfo); })
    done(null, userObj);
});

//
// Lighthouse Session Manager
//

export class LHSessionMgr {
    signinTmpl  : any;

    appName     : string;
    authConfig  : any;

    klass       : string;
    hostURL     : string;
    authPath    : string;
    successPath : string;
    failurePath : string;

    dbPort      : number;
    dbHost      : string;

    r           : any;  // rethinkdb(dash) database driver

    constructor(appName : string, hostURL : string, authConfig : any, options? : any) {
        var options = options || {};

        this.appName     = appName;
        this.hostURL     = hostURL;
        this.authConfig  = authConfig;

        this.klass       = options.klass       || "lh-identity";
        this.authPath    = options.authPath    || "/auth";
        this.successPath = options.successPath || '/';
        this.failurePath = options.failurePath || this.authPath + '/signin';

        this.dbHost      = options.dbHost      || 'localhost';
        this.dbPort      = options.dbPort      || 28035;

        // Open rethinkdb with connection pool, and set default database (works
        // even if UserIdentities doesn't yet exist)
        this.r = require('rethinkdbdash')({
            servers : [{host : this.dbHost, port : this.dbPort}],
            db : 'UserIdentities'
        }); 


        // DEBUGGING true ||
        if (true || options.initDatabase) {
            this.initDB();
        }

        this.signinTmpl = compileFile(path.resolve(__dirname, 'signin.tmpl.html'));

        var strategy;

        if (authConfig.facebook) {
            if (!authConfig.facebook.callbackURL) {
                authConfig.facebook.callbackURL = this.hostURL + this.authPath + '/facebook/callback';
            }

            // For Facebook, need to specify profileFields to fetch.  First, create copy
            var fbAuthConfig = (JSON.parse(JSON.stringify(authConfig.facebook)));

            // Then add profileFields
            fbAuthConfig.profileFields = ["id", "name", "displayName", "photos", "profileUrl", "email", "gender"];

            strategy = new FacebookStrategy(
                fbAuthConfig,
                this._handleAuthentication.bind(this)
            );

            passport.use(strategy);
        }

        if (authConfig.google) {
            if (!authConfig.google.callbackURL) {
                authConfig.google.callbackURL = this.hostURL + this.authPath + '/google/callback';
            }

            strategy = new GoogleStrategy(
                authConfig.google,
                this._handleAuthentication.bind(this)
            );

            passport.use(strategy);
        }
    }

    register(app : any) : void {
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
    }

    renderSignin() : string  {
        var html = this.signinTmpl({
            appName        : this.appName,
            klass          : this.klass,
            signinFacebook : this.authConfig.facebook ? this._signinURL('facebook') : '',
            signinGoogle   : this.authConfig.google   ? this._signinURL('google')   : ''
        });
        return html;
    }

    currentUserId(req) : boolean {
        if (req.isAuthenticated()) {
            // TODO: is this the proper way?
            return req['user'].id;
        }
        return null;
    }

    initDB() {
        var _r = this.r;

        console.log("initDB: About to create UserIdentities");

        _r.dbCreate("UserIdentities").run().finally(function() {
            console.log("initDB: About to create globals table");
            return _r.tableCreate('globals').run();

        }).finally(function() {
            console.log("initDB: About to insert userCount into globals table");
            return _r.table('globals').insert({
                id    : 'userCount',
                value : 0
            }).run();

        }).finally(function() {
            console.log("initDB: About to create users table");
            return _r.tableCreate('users').run();

        }).finally(function() {
            console.log("initDB: About to insert dummy user");
            return _r.table('users').insert({
                id           : 99,
                created      : new Date(),
            });

        }).finally(function() {
            console.log("initDB: About to create authProviders table");
            return _r.tableCreate('authProviders').run();

        }).finally(function() {
            console.log("initDB: About to insert dummy authProvider entry");
            return _r.table('authProviders').insert({
                id           : 'lh:99',
                userId       : 99,

                provider     : 'lh',
                providerId   : 99, // Lighthouse dummy userId

                username     : 'dummy@example.com',
                passwordHash : null,

                lastSignin   : null,

                emails       : ['dummy1@example.com', 'DUMMY2@example.com'],

                displayName  : 'Dummy User',
                name         : {
                    familyName : 'User',
                    givenName  : 'Dummy',
                    middleName : null
                },

                gender      : 'other',

                photos      : [],
                profileUrl  : ''
            }).run();

        }).finally(function() {
            console.log("initDB: About to create userIdIndex");
            return _r.table('authProviders').indexCreate('userIdIndex', _r.row('userId')).run();

        }).finally(function() {
            console.log("initDB: About to wait for userIdIndex");
            return _r.table('authProviders').indexWait('userIdIndex').run();

        }).finally(function() {
            console.log("initDB: About to create emailIndex");
	    return _r.table('authProviders').indexCreate('emailIndex', 
							 _r.row('emails').map(function(email) 
							 {
							     // need to use expr() to convert to an object that 
							     // ReQL commands can operate on
							     return _r.expr(email).downcase();
							 }),
                                                         {multi: true}).run();

        }).finally(function() {
            console.log("initDB: About to wait for emailIndex");
            return _r.table('authProviders').indexWait('emailIndex').run();

        }).finally(function() {
            console.log("initDB: Done!");
        });
    }

    // 
    // Private methods
    // 

    _registerRoutes(app, provider) {
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
        } else {
            // authenticateFn = passport.authenticate(provider);
            authenticateFn = passport.authenticate(provider, { scope: ['email'] });
        }

        app.get(self._signinURL(provider), 
                authenticateFn,
                function(req, res) {
                    console.log("In signin redirect !?");
                    // The request will be redirected to the provider for authentication, 
                    // so this function will not be called.
                });

        // GET /<authPath>/<provider>/callback
        //   Use passport.authenticate() as route middleware to authenticate the
        //   request.  If authentication fails, the user will be redirected back to the
        //   sign in page.  Otherwise, the primary route function function will be called,
        //   which, in this example, will redirect the user to the home page.

        var callbackAuthFn = passport.authenticate(provider,  { failureRedirect: self.failurePath });

        app.get(self._callbackURL(provider), 
                function(req, res, next) {
                    console.log("Authenticating callback");
                    return callbackAuthFn(req, res, next);
                },
                function(req, res) {
                    console.log("Successful authentication!, redirecting", self.successPath);
                    res.redirect(self.successPath);
                });
    };

    _handleAuthentication(accessToken, refreshToken, profile, done) {
        // asynchronous verification, for effect...
        process.nextTick(function () {

            // Special case for google (passport-google plugin is apparently missing this)
            if (!profile.profileUrl && profile._json.url) {
                profile.profileUrl = profile._json.url;
            }

            console.log("Successfully Authenticated" , profile);

            

            // Look up this user in the database.  If not found, try to find a 
            // matching user (only by email for now), and if not found, 

            // To keep the example simple, the user's profile is returned to
            // represent the logged-in user.  In a typical application, you would want
            // to associate the account with a user record in your database,
            // and return that user instead.
            return done(null, profile);
        });
    }

    _signinURL(provider) {
        return this.authPath + '/' + provider;
    }

    _callbackURL(provider) {
        return this.authPath + '/' + provider + '/callback';
    }

}
