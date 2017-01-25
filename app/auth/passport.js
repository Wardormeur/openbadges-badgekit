// load all the things we need
var LocalStrategy      = require('passport-local').Strategy;
var FacebookStrategy   = require('passport-facebook').Strategy;
var TwitterStrategy    = require('passport-twitter').Strategy;
var GoogleStrategy     = require('passport-google-oauth').OAuth2Strategy;
var DeviantArtStrategy = require('passport-deviantart').Strategy;
var BearerStrategy     = require('passport-http-bearer-base64').Strategy;
var PersonaStrategy    = require('passport-persona').Strategy;

const async = require('async');

// load up the user model
var Account = require('../models/account')("DATABASE");
//var Session = require('../models/backpack-connect').Session;

// load up our trusty password strength checker, courtesy of the sec experts over at owasp
var owasp = require('owasp-password-strength-test');


module.exports = function(passport) {

    // load the auth variables for third-party strategies other than persona
    // var configAuth = process.env.passportStrategyConfigs;

    // =========================================================================
    // PASSPORT SESSION SETUP ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users in/out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        Account.getOne({ id: id }, function(err, user) {
        	done(err, user);
        });
    });


    // =========================================================================
    // HTTP BEARER TOKEN LOGIN =================================================
    // =========================================================================
    // passport.use('bearer', new BearerStrategy({
    //         passReqToCallback  : true,
    //         base64EncodedToken : true
    //     },
    //     function(req, token, done) {
    //        Session.findOne({ access_token: token }, function (err, session) {
    //             if (err) { return done(err); }
    //             if (!session) { return done(null, false); }

    //             User.findById(session.attributes.user_id, function(err, user) {
    //                 if (err) { return done(err); }
    //                 if (!user) { return done(null, false); }
    //                 req.bpc_session = session;
    //                 return done(null, user, { scope: 'all' });
    //             });
    //         });
    //     }
    // ));

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    passport.use('local-login', new LocalStrategy({
        passwordField : 'password',
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
    function(req, username, password, done) {
        if (username)
            username = username.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching

        // asynchronous
        process.nextTick(function() {
            Account.getOne({ email:  username }, function(err, user) {
                // if there are any errors, return the error
                if (err)
                    return done(err);

                if (user) {
			user.last_login = Date.now();
			console.log(Account.methods.generateSalt());
			console.log(Account.methods.generateHash(password, user.salt));
			if (user.passwd == Account.methods.generateHash(password, user.salt)) {
				var query = {
					id: user.id,
					last_login: user.last_login
				};
				Account.put(query, function (err, result) {
    					if (err)
      						return callback(err);
					});
				req.session.email=user.email;
				return done(null, user);
			} else {
                       		return done(null, false, req.flash('error', 'Invallid password.'));
			}
                } else {
                       return done(null, false, req.flash('error', 'The email address used has no Badgekit account.  Please sign up for a new account.'));
                }
            });

        });

    }));

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'username',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
    function(req, username, password, done) {
        if (username)
            username = username.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching

        // asynchronous
        process.nextTick(function() {
            // if the user is not already logged in:
            if (!req.user) {
                 Account.getOne({ email:  username }, function(err, user) {
                    // if there are any errors, return the error
                    if (err)
                        return done(err);

                    // check if the password is secure
                    var result = owasp.test(password);

                    if (result.errors.length > 0) {
                      return done(null, false, req.flash('error', result.errors));
                    }

                    // check to see if theres already a user with that email
                    if (user) {
                        return done(null, false, req.flash('error', 'That email is already taken.'));
		    } else {
	                 // there is no login nor a logged in person
			 // start crating variables to setup new account
	                 // create the user
			 // hash password
			 var createdAt = new Date().getTime();
			 var salt = Account.methods.generateSalt();
			 password = Account.methods.generateHash(password,salt);
	                 var query = {
	                     email: username,
	                     passwd: password,
			     salt: salt,
			     active: 1,
	                     created_at: createdAt,
	                     updated_at: createdAt,
	                 };
	                 Account.put(query, function (err, result) {
	                     if (err)
	                          return callback(err);
			});

			//read the account to mem
		        Account.getOne({ email:  username }, function(err, user) {
	                   // if there are any errors, return the error
	                	if (err)
	                       		return done(err);
	                //if we got an account return a success
			return done(null,user);
			});
		    }});
            } else {
                // user is logged in and already has a local account. Ignore signup. (You should log out before trying to create a new account, user!)
                return done(null, req.user, req.flash('error', 'you already have an accoutn and are logged in please logout before signingup.'));
            }

        });

    }));

    // =========================================================================
    // FACEBOOK ================================================================
    // =========================================================================
    // passport.use(new FacebookStrategy({

    //     clientID        : configAuth.facebookAuth.clientID,
    //     clientSecret    : configAuth.facebookAuth.clientSecret,
    //     callbackURL     : configAuth.facebookAuth.callbackURL,
    //     passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

    // },
    // function(req, token, refreshToken, profile, done) {

    //     // asynchronous
    //     process.nextTick(function() {

    //         // check if the user is already logged in
    //         if (!req.user) {

    //             User.findOne({ 'facebook.id' : profile.id }, function(err, user) {
    //                 if (err)
    //                     return done(err);

    //                 if (user) {

    //                     // if there is a user id already but no token (user was linked at one point and then removed)
    //                     if (!user.facebook.token) {
    //                         user.facebook.token = token;
    //                         user.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName;
    //                         user.facebook.email = (profile.emails[0].value || '').toLowerCase();

    //                         user.save(function(err) {
    //                             if (err)
    //                                 return done(err);
                                    
    //                             return done(null, user);
    //                         });
    //                     }

    //                     return done(null, user); // user found, return that user
    //                 } else {
    //                     // if there is no user, create them
    //                     var newUser            = new User();

    //                     newUser.facebook.id    = profile.id;
    //                     newUser.facebook.token = token;
    //                     newUser.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName;
    //                     newUser.facebook.email = (profile.emails[0].value || '').toLowerCase();

    //                     newUser.save(function(err) {
    //                         if (err)
    //                             return done(err);
                                
    //                         return done(null, newUser);
    //                     });
    //                 }
    //             });

    //         } else {
    //             // user already exists and is logged in, we have to link accounts
    //             var user            = req.user; // pull the user out of the session

    //             user.facebook.id    = profile.id;
    //             user.facebook.token = token;
    //             user.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName;
    //             user.facebook.email = (profile.emails[0].value || '').toLowerCase();

    //             user.save(function(err) {
    //                 if (err)
    //                     return done(err);
                        
    //                 return done(null, user);
    //             });

    //         }
    //     });

    // }));

    // =========================================================================
    // TWITTER =================================================================
    // =========================================================================
    // passport.use(new TwitterStrategy({

    //     consumerKey     : configAuth.twitterAuth.consumerKey,
    //     consumerSecret  : configAuth.twitterAuth.consumerSecret,
    //     callbackURL     : configAuth.twitterAuth.callbackURL,
    //     passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

    // },
    // function(req, token, tokenSecret, profile, done) {

    //     // asynchronous
    //     process.nextTick(function() {

    //         // check if the user is already logged in
    //         if (!req.user) {

    //             User.findOne({ 'twitter.id' : profile.id }, function(err, user) {
    //                 if (err)
    //                     return done(err);

    //                 if (user) {
    //                     // if there is a user id already but no token (user was linked at one point and then removed)
    //                     if (!user.twitter.token) {
    //                         user.twitter.token       = token;
    //                         user.twitter.username    = profile.username;
    //                         user.twitter.displayName = profile.displayName;

    //                         user.save(function(err) {
    //                             if (err)
    //                                 return done(err);
                                    
    //                             return done(null, user);
    //                         });
    //                     }

    //                     return done(null, user); // user found, return that user
    //                 } else {
    //                     // if there is no user, create them
    //                     var newUser                 = new User();

    //                     newUser.twitter.id          = profile.id;
    //                     newUser.twitter.token       = token;
    //                     newUser.twitter.username    = profile.username;
    //                     newUser.twitter.displayName = profile.displayName;

    //                     newUser.save(function(err) {
    //                         if (err)
    //                             return done(err);
                                
    //                         return done(null, newUser);
    //                     });
    //                 }
    //             });

    //         } else {
    //             // user already exists and is logged in, we have to link accounts
    //             var user                 = req.user; // pull the user out of the session

    //             user.twitter.id          = profile.id;
    //             user.twitter.token       = token;
    //             user.twitter.username    = profile.username;
    //             user.twitter.displayName = profile.displayName;

    //             user.save(function(err) {
    //                 if (err)
    //                     return done(err);
                        
    //                 return done(null, user);
    //             });
    //         }

    //     });

    // }));

    // =========================================================================
    // GOOGLE ==================================================================
    // =========================================================================
    // passport.use(new GoogleStrategy({

    //     clientID        : configAuth.googleAuth.clientID,
    //     clientSecret    : configAuth.googleAuth.clientSecret,
    //     callbackURL     : configAuth.googleAuth.callbackURL,
    //     passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

    // },
    // function(req, token, refreshToken, profile, done) {

    //     // asynchronous
    //     process.nextTick(function() {

    //         // check if the user is already logged in
    //         if (!req.user) {

    //             User.findOne({ 'google.id' : profile.id }, function(err, user) {
    //                 if (err)
    //                     return done(err);

    //                 if (user) {

    //                     // if there is a user id already but no token (user was linked at one point and then removed)
    //                     if (!user.google.token) {
    //                         user.google.token = token;
    //                         user.google.name  = profile.displayName;
    //                         user.google.email = (profile.emails[0].value || '').toLowerCase(); // pull the first email

    //                         user.save(function(err) {
    //                             if (err)
    //                                 return done(err);

    //                             return done(null, user);
    //                         });
    //                     }

    //                     return done(null, user);
    //                 } else {
    //                     var newUser          = new User();

    //                     newUser.google.id    = profile.id;
    //                     newUser.google.token = token;
    //                     newUser.google.name  = profile.displayName;
    //                     newUser.google.email = (profile.emails[0].value || '').toLowerCase(); // pull the first email

    //                     newUser.save(function(err) {
    //                         if (err)
    //                             return done(err);
                                
    //                         return done(null, newUser);
    //                     });
    //                 }
    //             });

    //         } else {
    //             // user already exists and is logged in, we have to link accounts
    //             var user               = req.user; // pull the user out of the session

    //             user.google.id    = profile.id;
    //             user.google.token = token;
    //             user.google.name  = profile.displayName;
    //             user.google.email = (profile.emails[0].value || '').toLowerCase(); // pull the first email

    //             user.save(function(err) {
    //                 if (err)
    //                     return done(err);
                        
    //                 return done(null, user);
    //             });

    //         }

    //     });

    // }));


    // =========================================================================
    // DEVIANTART ==============================================================
    // =========================================================================
    // passport.use(new DeviantArtStrategy({

    //     clientID        : configAuth.deviantArt.clientID,
    //     clientSecret    : configAuth.deviantArt.clientSecret,
    //     callbackURL     : configAuth.deviantArt.callbackURL,
    //     passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

    // },
    // function(req, token, refreshToken, profile, done) {

    //     // asynchronous
    //     process.nextTick(function() {

    //         // check if the user is already logged in
    //         if (!req.user) {

    //             User.findOne({ 'deviantart.id' : profile.id }, function(err, user) {
    //                 if (err)
    //                     return done(err);

    //                 if (user) {

    //                     // if there is a user id already but no token (user was linked at one point and then removed)
    //                     if (!user.deviantart.token) {
    //                         user.deviantart.token = token;
    //                         user.deviantart.id  = profile.id;
    //                         user.deviantart.username = profile.username;

    //                         user.save(function(err) {
    //                             if (err)
    //                                 return done(err);
                                    
    //                             return done(null, user);
    //                         });
    //                     }

    //                     return done(null, user);
    //                 } else {
    //                     var newUser          = new User();

    //                     newUser.deviantart.token = token;
    //                     newUser.deviantart.id    = profile.id;
    //                     newUser.deviantart.username  = profile.username;

    //                     newUser.save(function(err) {
    //                         if (err)
    //                             return done(err);
                                
    //                         return done(null, newUser);
    //                     });
    //                 }
    //             });

    //         } else {
    //             // user already exists and is logged in, we have to link accounts
    //             var user               = req.user; // pull the user out of the session

    //             user.deviantart.id    = profile.id;
    //             user.deviantart.token = token;
    //             user.deviantart.username  = profile.username;

    //             user.save(function(err) {
    //                 if (err)
    //                     return done(err);
                        
    //                 return done(null, user);
    //             });

    //         }

    //     });

    // }));

};
