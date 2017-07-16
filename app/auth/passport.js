// load all the things we need
var LocalStrategy = require('passport-local').Strategy;

const async = require('async');

// load up the user model
var Account = require('../models/account')("DATABASE");

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
    Account.getOne({
      id: id
    }, function(err, user) {
      done(err, user);
    });
  });

  // LOCAL LOGIN =============================================================
  // =========================================================================
  passport.use('local-login', new LocalStrategy({
      passwordField: 'password',
      passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
    function(req, username, password, done) {
      if (username)
        username = username.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching

      // asynchronous
      process.nextTick(function() {
        Account.getOne({
          email: username
        }, function(err, user) {
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
              Account.put(query, function(err, result) {
                if (err)
                  return callback(err);
              });
              req.session.email = user.email;
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
      usernameField: 'username',
      passwordField: 'password',
      passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
    function(req, username, password, done) {
      if (username)
        username = username.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching

      // asynchronous
      process.nextTick(function() {
        // if the user is not already logged in:
        if (!req.user) {
          Account.getOne({
            email: username
          }, function(err, user) {
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
            }
          });
        }
      });
    }));
};
