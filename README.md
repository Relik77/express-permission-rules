Node.js: bitwise-operation
=================


An Express permission system for ensure user permission on route, inspired by the Access Control Filter on the Yii PHP framework.



Installation
------------
**Node.js** `npm install --save express-permission-rules`

**Require in Node** `var ExpressPermissions = require('express-permission-rules');`


Usage
-----
```js
var express            = require('express');
var ExpressPermissions = require('express-permission-rules');
var app                = express();
var router             = express.Router();

app.use('/', router);

// Compatible with `Passport` authentication middleware
var passport           = require('passport');

ExpressPermissions.setConfig({
    redirectUrl: '/home',
    userProperty: 'user',
    rolenameProperty: 'userRoles',
    loginProperty: 'userLogin'
});

// Consider an passport authentication strategy 'bearer'
// @see https://www.npmjs.com/package/passport-http-bearer
ExpressPermissions.authenticate = function(req, res, next) {
    passport.authenticate('bearer', {session: true, failWithError: true})(req, res, next);
};


// You can set All permissions rules with a json
ExpressPermissions.setRules([
    [
        'allow',
        {
            paths: ["/profile"],
            methods: ['get'],
            users: ['@']
        }
    ],
    [
        'deny',
        {
            paths: ["/profile"],
            users: ['*']
        }
    ]
]);

app.use(ExpressPermissions.middleware());

router.get('/profile',
    function(req, res) {
        // Only connected users can access
        res.end('ok');
    });


// Or set rules in each routes
router.post('/profile',
    ExpressPermissions.ensurePermitted([
        ['allow', {
            users: '@'
        }],
        ['deny', {
            users: '*'
        }]
    ]),
    function(req, res) {
        // Only connected users can access
        res.end('ok');
    });

```


Access Rules
------------

The access rules are evaluated one by one in the order they are specified.
The first rule that matches the current pattern (e.g. username, roles, client IP) determines the authorization result.
If this rule is an allow rule, the action can be executed; if it is a deny rule, the action cannot be executed; if none of the rules matches the context, the action can still be executed.

**Tip:** To ensure an action does not get executed under certain contexts, it is beneficial to always specify a matching-all deny rule at the end of rule set, like the following:

```js
[
    // ... other rules ...
    ['deny', {
        users: ['*']
    }]
]
```

An access rule can match the following context parameters:

- **paths:** specifies which Urls this rule matches. A path can be a string or a RegExp.

- **methods:** specifies which methods this rule matches. (get, post, put, delete...)

- **users:** specifies which users this rule matches. The current user's name is used for matching. Three special characters can be used here:
    - *: any user, including both anonymous and authenticated users.
    - ?: anonymous users.
    - @: authenticated users.

- **roles:** specifies which roles that this rule matches.

- **ips:** specifies which client IP addresses this rule matches.

- **expression:** specifies a JS expression whose value indicates whether this rule matches. In the expression, you can use variables req, res and user.


Methods
-------
- [setConfig](#setConfig)
- [authenticate](#authenticate)
- [permissionDenied](#permissionDenied)
- [setRules](#setRules)
- [middleware](#middleware)
- [ensurePermitted](#ensurePermitted)
- [ensurePermitted.users](#ensurePermitted)
- [ensurePermitted.roles](#ensurePermitted)
- [ensurePermitted.ips](#ensurePermitted)
- [ensurePermitted.expression](#ensurePermitted)


### setConfig()

ExpressPermissions's primary initialization middleware.

Options:
- `redirectUrl`       Url to redirect user if user can not access to requested url
- `userProperty`      Property to get current user on `req` after login, defaults to 'user'
- `rolenameProperty`  Property to get user roles on current user
- `loginProperty`     Property to get user login on current user

```js
var ExpressPermissions = require('express-permission-rules');

ExpressPermissions.setConfig({
    redirectUrl: '/home',
    userProperty: 'user',
    rolenameProperty: 'userRoles',
    loginProperty: 'userLogin'
});
```


### authenticate()

This function must be overridden by an authenticate method, It will be used to attempt to automatically connect the user.

```js
var ExpressPermissions = require('express-permission-rules');

ExpressPermissions.authenticate = function(req, res, next) {
    passport.authenticate('bearer', {session: true, failWithError: true})(req, res, next);
};
```

### permissionDenied()

This function can be overridden, by default it redirect the user if user can not access to the requested url

```js
var ExpressPermissions = require('express-permission-rules');

ExpressPermissions.permissionDenied = function(req, res, next) {
    var self = this;

    if (self.config.redirectUrl
        && req.originalUrl != self.config.redirectUrl
        && !req.originalUrl.match(/^\/api\//)) {
        res.redirect(self.config.redirectUrl);
    } else {
        next(new PermissionError());
    }
};
```

### setRules()

This function define permissions of your application.

```js
var ExpressPermissions = require('express-permission-rules');

ExpressPermissions.setRules([
    [
        'allow',
        {
            paths: ["/profile"],
            methods: ['get'],
            users: ['@']
        }
    ],
    [
        'deny',
        {
            paths: ["/profile"],
            users: ['*']
        }
    ]
]);
```

### middleware()

This function is used to connect ExpressPermissions to your app.

```js
var ExpressPermissions = require('express-permission-rules');

ExpressPermissions.setRules([
    // .... rules ....
]);

app.use(ExpressPermissions.middleware());
```

### ensurePermitted()

You can also set rules in each routes.

```js
var ExpressPermissions = require('express-permission-rules');
var router             = express.Router();

router.get('/home',
    ExpressPermissions.ensurePermitted([
        ['allow', {
            users: '@'
        }],
        ['deny', {
            users: '*'
        }]
    ]),
    function(req, res) {
        res.end('ok');
    });;
```

If you use only one access rule, rules can be simplified:

```js
var ExpressPermissions = require('express-permission-rules');
var router             = express.Router();

router.get('/home',
    ExpressPermissions.ensurePermitted.users([
        ['allow', '@'],
        ['deny', '*']
    ]),
    function(req, res) {
        res.end('ok');
    });


router.get('/admin',
    ExpressPermissions.ensurePermitted.roles([
        ['allow', 'admin'],
        ['deny', '*']
    ]),
    function(req, res) {
        res.end('ok');
    });
```
