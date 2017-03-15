var util  = require('util'),
    async = require('async'),
    _     = require('underscore'),
    S     = require('string');

function PermissionError(message) {
    this.name = 'PermissionError';
    this.message = message || 'Permission denied';
    this.status = 403;
    this.code = 1;
}
util.inherits(PermissionError, Error);

function PermissionRules() {
    var self = this;
    this.config = {
        redirectUrl: '/',
        userProperty: 'user',
        rolenameProperty: 'role',
        loginProperty: 'login'
    };
    this.rules = [];
    this.validators = {
        users: function (req, users) {
            if (!Array.isArray(users)) users = [users];
            if (users.length == 0) return true;
            if (_.contains(users, '*')) return true; // anyone can access ?
            if (_.contains(users, '?') && !req[self.config.userProperty]) return true; // guest can access ?
            if (_.contains(users, '@') && req[self.config.userProperty]) return true; // guest can access ?
            if (req[self.config.userProperty] && _.contains(users, req[self.config.userProperty][self.config.loginProperty])) return true; // this member can access ?

            return false;
        },
        roles: function (req, roles) {
            if (!Array.isArray(roles)) roles = [roles];
            if (roles.length == 0) return true;
            if (_.contains(roles, '*')) return true;
            if (!req[self.config.userProperty]) return false;

            var role_name = req[self.config.userProperty];
            self.config.rolenameProperty.split('.').forEach(function (name) {
                if (role_name && role_name[name] != undefined) {
                    role_name = role_name[name];
                } else {
                    role_name = undefined;
                }
            });
            if (role_name !== undefined && !Array.isArray(role_name)) {
                role_name = [role_name];
            }

            return (role_name !== undefined && _.intersection(roles, role_name).length > 0);
        },
        ips: function (req, ips) {
            var clientIp = (req.headers['x-forwarded-for'] || '').split(',')[0] || req.connection.remoteAddress;

            if (!Array.isArray(ips)) ips = [ips];
            if (ips.length == 0) return true;
            if (_.contains(ips, '*')) return true; // anyone can access ?
            if (_.contains(ips, clientIp)) return true; // this ip can access ?

            return !!_.find(ips, function (ip) {
                var starpos = ip.indexOf('*');

                if (starpos < 0) return false;
                return clientIp.substr(0, starpos) == ip.substr(0, starpos);
            });
        },
        expression: function (req, res, expression, callback) {
            if (typeof expression == "string") expression = new Function("req", "res", "user", expression);
            if (typeof expression != "function") return callback(null, false);

            switch (expression.length) {
                case 0:
                case 1:
                    return callback(null, !!expression(req[self.config.userProperty]));
                case 2:
                    return expression(req[self.config.userProperty], callback);
                case 3:
                    return callback(null, !!expression(req, res, req[self.config.userProperty]));
                case 4:
                    return expression(req, res, req[self.config.userProperty], callback);
                case 5:
                default:
                    return expression(req, res, req[self.config.userProperty], function (result) {
                        callback(null, !!result);
                    }, function (err) {
                        callback(err, false);
                    });
            }
        }
    };
}
PermissionRules.prototype.setConfig = function (options) {
    var self = this;

    _.keys(self.config).forEach(function (key) {
        if (options[key]) self.config[key] = options[key];
    });
};
PermissionRules.prototype.setRules = function (rules) {
    this.rules = _.chain(rules)
        .map(function (rule) {
            var rules = rule.pop() || {};

            rules.allowed = rule.shift();

            if (rules.path) rules.paths = rules.path;
            if (!Array.isArray(rules.paths)) rules.paths = [rules.paths];
            rules.paths = _.chain(rules.paths)
                .filter(function (path) {
                    return typeof path == "string" || path instanceof RegExp;
                })
                .map(function (path) {
                    if (!path instanceof RegExp) {
                        path = new RegExp("^" + S(path).ensureLeft('/').s + "(/|$)", "i");
                    }
                    return path;
                })
                .value();

            if (rules.method) rules.methods = rules.method;
            if (!rules.methods) rules.methods = [];
            else if (!Array.isArray(rules.methods)) rules.methods = [rules.methods];
            rules.methods = rules.methods.map(function (method) {
                return method.toUpperCase();
            });

            if (rules.user) rules.users = rules.user;
            if (rules.users && !Array.isArray(rules.users)) rules.users = [rules.users];

            if (rules.role) rules.roles = rules.role;
            if (rules.roles && !Array.isArray(rules.roles)) rules.roles = [rules.roles];

            if (rules.ip) rules.ips = rules.ip;
            if (rules.ips && !Array.isArray(rules.ips)) rules.ips = [rules.ips];

            if (typeof rules.expression == "string") {
                rules.expression = new Function("req", "res", "user", rules.expression);
            } else if (typeof rules.expression != "function") {
                delete rules.expression;
            }

            return _.pick({
                allowed: rules.allowed == 'allow',
                paths: rules.paths,
                methods: rules.methods,
                users: rules.users,
                roles: rules.roles,
                ips: rules.ips,
                expression: rules.expression
            }, function(value) {
                return value !== undefined;
            });
        })
        .filter(function (rule) {
            return rule.paths.length > 0;
        })
        .value();
};
PermissionRules.prototype.setValidator = function(name, fct) {
    var self = this;

    this.validators[name] = fct;
    PermissionRules.prototype.ensurePermitted[name] = function(rules) {
        if (!Array.isArray(rules)) rules = [rules];

        return function(req, res, next) {
            var args = Array.prototype.slice.call(arguments);
            req = args.shift();
            next = args.pop();
            res = args.shift();

            async.detectSeries(rules, function (rule, callback) {
                var values = _.last(rule);

                authenticate(function () {
                    switch (self.validators[name].length) {
                        case 0:
                        case 1:
                            return self.validators[name].call(self, callback);
                        case 2:
                            return callback(null, !!self.validators[name].call(self, req, values));
                        case 3:
                            return self.validators[name].call(self, req, values, callback);
                        case 4:
                            return self.validators[name].call(self, req, res, values, callback);
                        case 5:
                        default:
                            return self.validators[name].call(self, req, res, values, function (result) {
                                callback(null, !!result);
                            }, function (err) {
                                callback(err, false);
                            });
                    }
                });
            }, function (err, rule) {
                var allowed = _.first(rule);

                if (err) return next(err);
                if (!rule || allowed == 'allow') return next();
                self.permissionDenied(req, res, next);
            });

            function authenticate(callback) {
                if (req[self.config.userProperty]) return callback();

                self.authenticate(req, res, function(err) {
                    if (err) return self.permissionDenied(req, res, next);
                    callback();
                });
            }
        };
    };
};
PermissionRules.prototype.permissionDenied = function (req, res, next) {
    var self = this;

    if (self.config.redirectUrl
        && req.originalUrl != self.config.redirectUrl
        && !req.originalUrl.match(/^\/api\//)) {
        res.redirect(self.config.redirectUrl);
    } else {
        next(new PermissionError());
    }
};
PermissionRules.prototype.authenticate = function (callback) {
    throw new Error('PermissionRules#authenticate must be overridden');
};
PermissionRules.prototype.middleware = function () {
    var self = this;

    return function (req, res, next) {
        async.detectSeries(self.rules, function (rule, callback) {
            if (rule.methods.length > 0 && !_.contains(rule.methods, req.method.toUpperCase())) {
                return callback(null, false);
            }

            if (!_.find(rule.paths, function (path) {
                    return req.originalUrl.match(path)
                })) {
                return callback(null, false);
            }

            authenticate(rule, function () {
                async.every(_.chain(rule)
                        .keys()
                        .without('allowed', 'paths', 'methods')
                        .value(),
                    function (key, callback) {
                        if (typeof self.validators[key] != "function") {
                            return callback(null, true);
                        }
                        switch (self.validators[key].length) {
                            case 0:
                            case 1:
                                return self.validators[key].call(self, callback);
                            case 2:
                                return callback(null, !!self.validators[key].call(self, req, rule[key]));
                            case 3:
                                return self.validators[key].call(self, req, rule[key], callback);
                            case 4:
                                return self.validators[key].call(self, req, res, rule[key], callback);
                            case 5:
                            default:
                                return self.validators[key].call(self, req, res, rule[key], function (result) {
                                    callback(null, !!result);
                                }, function (err) {
                                    callback(err, false);
                                });
                        }
                    }, callback);
            });
        }, function (err, rule) {
            if (err) return next(err);
            if (!rule || rule.allowed) return next();
            self.permissionDenied(req, res, next);
        });

        function authenticate(rule, callback) {
            if (req[self.config.userProperty]) return callback();
            if (rule.users && !Array.isArray(rule.users)) rule.users = [rule.users];
            if (rule.roles && !Array.isArray(rule.roles)) rule.roles = [rule.roles];

            if ((!rule.users || (rule.users.length == 0 || _.contains(rule.users, '*')))
                && (!rule.roles || rule.roles.length == 0)
                && !rule.expression) return callback();

            self.authenticate(req, res, function(err) {
                if (err) return self.permissionDenied(req, res, next);
                callback();
            });
        }
    };
};

/**
 *
 *  ExpressPermissions.ensurePermitted([
 *     ['allow',
 *         {
 *             roles: ['super-admin', 'admin'],
 *             users: ['nom', '@', '?', '*'], // @ = member (connected), ? = guest (not connected), * = anyone
 *             ips: ['192.168.0.1', '192.168.0.*', '192.168.*', '*'], // 192.168.0.* = all ips starting by 192.168.0., * = all ips
 *             expression: "user.email != ''" // must return 'true' for match
 *         } // If all the rules above match, the user has the permission to access.
 *     ],
 *     ['deny',
 *         {
 *             users:'*'
 *         }
 *     ]
 *  ]);
 *
 * @param rules
 */
PermissionRules.prototype.ensurePermitted = function (rules) {
    var self = this;

    if (!Array.isArray(rules)) rules = [rules];

    return function (req, res, next) {
        async.detectSeries(rules, function (rule, callback) {
            rule = _.last(rule);

            authenticate(rule, function () {
                async.every(_.keys(rule),
                    function (key, callback) {
                        if (typeof self.validators[key] != "function") {
                            return callback(null, true);
                        }
                        switch (self.validators[key].length) {
                            case 0:
                            case 1:
                                return self.validators[key].call(self, callback);
                            case 2:
                                return callback(null, !!self.validators[key].call(self, req, rule[key]));
                            case 3:
                                return self.validators[key].call(self, req, rule[key], callback);
                            case 4:
                                return self.validators[key].call(self, req, res, rule[key], callback);
                            case 5:
                            default:
                                return self.validators[key].call(self, req, res, rule[key], function (result) {
                                    callback(null, !!result);
                                }, function (err) {
                                    callback(err, false);
                                });
                        }
                    }, callback);
            });
        }, function (err, rule) {
            var allowed = _.first(rule);

            if (err) return next(err);
            if (!rule || allowed == 'allow') return next();
            self.permissionDenied(req, res, next);
        });

        function authenticate(rule, callback) {
            if (req[self.config.userProperty]) return callback();
            if (rule.users && !Array.isArray(rule.users)) rule.users = [rule.users];
            if (rule.roles && !Array.isArray(rule.roles)) rule.roles = [rule.roles];

            if ((!rule.users || (rule.users.length == 0 || _.contains(rule.users, '*')))
                && (!rule.roles || rule.roles.length == 0)
                && !rule.expression) return callback();

            self.authenticate(req, res, function(err) {
                if (err) return self.permissionDenied(req, res, next);
                callback();
            });
        }
    };
};

/**
 *
 *  ExpressPermissions.ensurePermitted.users([
 *      ['allow', '@'],
 *      ['deny', '*']
 *  ]);
 *
 * @param rules
 */
PermissionRules.prototype.ensurePermitted.users = function (rules) {
    var self = this;

    if (!Array.isArray(rules)) rules = [rules];

    return function(req, res, next) {
        var args = Array.prototype.slice.call(arguments);
        req = args.shift();
        next = args.pop();
        res = args.shift();

        async.detectSeries(rules, function (rule, callback) {
            var users = _.last(rule);

            authenticate(users, function () {
                callback(null, self.validators.users.call(self, req, users));
            });
        }, function (err, rule) {
            var allowed = _.first(rule);

            if (err) return next(err);
            if (!rule || allowed == 'allow') return next();
            self.permissionDenied(req, res, next);
        });

        function authenticate(users, callback) {
            if (!Array.isArray(users)) users = [users];
            if (req[self.config.userProperty]
                || _.contains(users, '*')) return callback();

            self.authenticate(req, res, function(err) {
                if (err) return self.permissionDenied(req, res, next);
                callback();
            });
        }
    };
};
PermissionRules.prototype.ensurePermitted.roles = function (rules) {
    var self = this;

    if (!Array.isArray(rules)) rules = [rules];

    return function(req, res, next) {
        var args = Array.prototype.slice.call(arguments);
        req = args.shift();
        next = args.pop();
        res = args.shift();

        async.detectSeries(rules, function (rule, callback) {
            var roles = _.last(rule);

            authenticate(roles, function () {
                callback(null, self.validators.roles.call(self, req, roles));
            });
        }, function (err, rule) {
            var allowed = _.first(rule);

            if (err) return next(err);
            if (!rule || allowed == 'allow') return next();
            self.permissionDenied(req, res, next);
        });

        function authenticate(roles, callback) {
            if (req[self.config.userProperty]) return callback();

            self.authenticate(req, res, function(err) {
                if (err) return self.permissionDenied(req, res, next);
                callback();
            });
        }
    }
};
PermissionRules.prototype.ensurePermitted.ips = function (rules) {
    var self = this;

    if (!Array.isArray(rules)) rules = [rules];

    return function(req, res, next) {
        var args = Array.prototype.slice.call(arguments);
        req = args.shift();
        next = args.pop();
        res = args.shift();

        async.detectSeries(rules, function (rule, callback) {
            callback(null, self.validators.ips.call(self, req, _.last(rule)));
        }, function (err, rule) {
            var allowed = _.first(rule);

            if (err) return next(err);
            if (!rule || allowed == 'allow') return next();
            self.permissionDenied(req, res, next);
        });
    }
};
PermissionRules.prototype.ensurePermitted.expression = function (rules) {
    var self = this;

    if (!Array.isArray(rules)) rules = [rules];

    return function(req, res, next) {
        var args = Array.prototype.slice.call(arguments);
        req = args.shift();
        next = args.pop();
        res = args.shift();

        async.detectSeries(rules, function (rule, callback) {
            authenticate(function () {
                callback(null, self.validators.expression.call(self, req, res, _.last(rule)));
            });
        }, function (err, rule) {
            var allowed = _.first(rule);

            if (err) return next(err);
            if (!rule || allowed == 'allow') return next();
            self.permissionDenied(req, res, next);
        });

        function authenticate(callback) {
            if (req[self.config.userProperty]) return callback();

            self.authenticate(req, res, function(err) {
                if (err) return self.permissionDenied(req, res, next);
                callback();
            });
        }
    }
};

module.exports = new PermissionRules();
