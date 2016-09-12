var util = require('util');
var LocalStrategy = require('passport-local').Strategy;
var BadRequestError = require('./badrequesterror');
var md5 = require('md5');
var sha1 = require('simple-sha1');

module.exports = function(schema, options) {
    options = options || {};
    options.iterations = options.iterations || 25000;
    options.keylen = options.keylen || 512;
    options.encoding = options.encoding || 'hex';

    // Populate field names with defaults if not set
    options.usernameField = options.usernameField || 'username';

    // option to convert username to lowercase when finding
    options.usernameLowerCase = options.usernameLowerCase || false;

    options.hashField = options.hashField || 'hash';
    if (options.limitAttempts){
      options.lastLoginField = options.lastLoginField || 'last';
      options.attemptsField = options.attemptsField || 'attempts';
      options.interval = options.interval || 100; // 100 ms
    }

    options.incorrectPasswordError = options.incorrectPasswordError || 'Incorrect password';
    options.incorrectUsernameError = options.incorrectUsernameError || 'Incorrect %s';
    options.missingUsernameError = options.missingUsernameError || 'Field %s is not set';
    options.missingPasswordError = options.missingPasswordError || 'Password argument not set!';
    options.userExistsError = options.userExistsError || 'User already exists with %s %s';
    options.attemptTooSoonError = options.attemptTooSoonError || 'Login attempted too soon after previous attempt';

    var schemaFields = {};
    if (!schema.path(options.usernameField)) {
    	schemaFields[options.usernameField] = String;
    }
    schemaFields[options.hashField] = String;
    if (options.limitAttempts){
      schemaFields[options.attemptsField] = {type: Number, default: 0};
      schemaFields[options.lastLoginField] = {type: Date, default: Date.now};
    }

    schema.add(schemaFields);

    schema.pre('save', function(next) {
        // if specified, convert the username to lowercase
        if (options.usernameLowerCase) {
            this[options.usernameField] = this[options.usernameField].toLowerCase();
        }

        next();
    });

    schema.methods.setPassword = function (password, cb) {
        if (!password) {
            return cb(new BadRequestError(options.missingPasswordError));
        }

        var self = this;
        var salt = md5((new Date()).valueOf()).substr(0,10);
        sha1(salt + passwd, function(hash){
            hashed = salt + hash.substr(0,30);
            self.set(options.hashField, hashed);
            cb(null, self);
        })
    };

    schema.methods.authenticate = function(password, cb) {
        var self = this;

        if (options.limitAttempts && (Date.now() - this.get(options.lastLoginField) < Math.pow(options.interval, this.get(options.attemptsField) + 1))){
            // This login attempt is too soon after the previous attempt
            this.set(options.lastLoginField, Date.now());
            self.save();
            return cb(null, false, { message: options.attemptTooSoonError });
        }

        salt = self.get(options.hashField).substr(0,10);
        sha1(salt + password, function(hash){
          hashed = salt + hash.substr(0,30);
          if (hashed == self.get(options.hashField)) {
              /* self.set(options.lastLoginField, Date.now()); */
              /* self.set(options.attemptsField, 0); */
              self.save();
              return cb(null, self);
          } else {
              if (options.limitAttempts){
                  self.set(options.lastLoginField, Date.now());
                  self.set(options.attemptsField, self.get(options.attemptsField) + 1);
                  self.save();
              }
              return cb(null, false, { message: options.incorrectPasswordError });
          }
        })
    };

    schema.statics.authenticate = function() {
        var self = this;

        return function(username, password, cb) {
            self.findByUsername(username, function(err, user) {
                if (err) { return cb(err); }

                if (user) {
                    return user.authenticate(password, cb);
                } else {
                    return cb(null, false, { message: util.format(options.incorrectUsernameError, options.usernameField) })
                }
            });
        }
    };

    schema.statics.serializeUser = function() {
        return function(user, cb) {
            cb(null, user.get(options.usernameField));
        }
    };

    schema.statics.deserializeUser = function() {
        var self = this;

        return function(username, cb) {
            self.findByUsername(username, cb);
        }
    };

    schema.statics.register = function(user, password, cb) {
        // Create an instance of this in case user isn't already an instance
        if (!(user instanceof this)) {
            user = new this(user);
        }

        if (!user.get(options.usernameField)) {
            return cb(new BadRequestError(util.format(options.missingUsernameError, options.usernameField)));
        }

        var self = this;
        self.findByUsername(user.get(options.usernameField), function(err, existingUser) {
            if (err) { return cb(err); }

            if (existingUser) {
                return cb(new BadRequestError(util.format(options.userExistsError, options.usernameField, user.get(options.usernameField))));
            }

            user.setPassword(password, function(err, user) {
                if (err) {
                    return cb(err);
                }

                user.save(function(err) {
                    if (err) {
                        return cb(err);
                    }

                    cb(null, user);
                });
            });
        });
    };

    schema.statics.findByUsername = function(username, cb) {
        var queryParameters = {};

        // if specified, convert the username to lowercase
        if (username !== undefined && options.usernameLowerCase) {
            username = username.toLowerCase();
        }

        queryParameters[options.usernameField] = username;

        var query = this.findOne(queryParameters);
        if (options.selectFields) {
            query.select(options.selectFields);
        }

        if (options.populateFields) {
            query.populate(options.populateFields);
        }

        if (cb) {
            query.exec(cb);
        } else {
            return query;
        }
    };

    schema.statics.createStrategy = function() {
        return new LocalStrategy(options, this.authenticate());
    };
};
