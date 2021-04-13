import * as async                          from "async";
import { NextFunction, Request, Response } from "express-serve-static-core";
import * as S                              from "string";
import * as _                              from "underscore";
import { expressPermissionRules }          from "./ExpressPermissionRules.interface";
import { PermissionError }                 from "./PermissionError";
import { expressionValidator }             from "./validators/expression-validator";
import { ipsValidator }                    from "./validators/ips-validator";
import { rolesValidator }                  from "./validators/roles-validator";
import { userValidator }                   from "./validators/users-validator";
import { ValidatorFct }                    from "./validators/validator.interface";
import PermissionRule = expressPermissionRules.PermissionRule;
import PermissionRules = expressPermissionRules.PermissionRules;
import PermissionRulesOptions = expressPermissionRules.PermissionRulesOptions;

interface PermissionRuleAllowed extends PermissionRule {
    allowed: boolean;
    paths: Array<RegExp>;
}

export abstract class ExpressPermissionRules {
    private config: PermissionRulesOptions             = {
        redirectUrl     : "/",
        userProperty    : "user",
        rolenameProperty: "role",
        loginProperty   : "login"
    };
    private validators: Map<string, ValidatorFct<any>> = new Map<string, ValidatorFct<any>>();
    private rules: Array<PermissionRuleAllowed>        = [];
    
    constructor(options: PermissionRulesOptions) {
        if (options.redirectUrl) this.config.redirectUrl = options.redirectUrl;
        if (options.userProperty) this.config.userProperty = options.userProperty;
        if (options.rolenameProperty) this.config.rolenameProperty = options.rolenameProperty;
        if (options.loginProperty) this.config.loginProperty = options.loginProperty;
        
        this.setValidator("users", userValidator(this.config.userProperty as string, this.config.loginProperty as string));
        this.setValidator("roles", rolesValidator(this.config.userProperty as string, this.config.rolenameProperty as string));
        this.setValidator("ips", ipsValidator());
        this.setValidator("expression", expressionValidator(this.config.userProperty as string));
    }
    
    public setRules(rules: Array<PermissionRules>) {
        this.rules = this.alignRules(rules);
    }
    
    public setValidator(name: string, validatorFct: ValidatorFct<any>) {
        this.validators.set(name, validatorFct);
    }
    
    public middleware() {
        return (req: Request, res: Response, next: NextFunction) => {
            const user = _.property(this.config.userProperty as string)(req);
            if (user) return this.validateRules(this.rules, req, res, next);
            this.authenticate(req, res, () => this.validateRules(this.rules, req, res, next));
        };
    }
    
    public ensurePermitted(rules: Array<PermissionRules>) {
        return (req: Request, res: Response, next: NextFunction) => {
            const user = _.property(this.config.userProperty as string)(req);
            if (user) return this.validateRules(this.rules, req, res, next);
            this.authenticate(req, res, () => this.validateRules(this.alignRules(rules), req, res, next));
        };
    }
    
    protected abstract authenticate(req: Request, res: Response, next: NextFunction): void;
    
    protected permissionDenied(error: PermissionError, req: Request, res: Response, next: NextFunction) {
        if (req.headers.accept == "application/json") {
            return next(error);
        }
        
        if (this.config.redirectUrl && req.originalUrl != this.config.redirectUrl) {
            return res.redirect(this.config.redirectUrl);
        }
        
        return next(error);
    }
    
    private alignRules(rules: Array<PermissionRules>): Array<PermissionRuleAllowed> {
        return _.chain(rules)
                .map((permissionRules: PermissionRules) => {
                    const permissionRule: PermissionRule               = permissionRules[1];
                    const permissionRuleAllowed: PermissionRuleAllowed = {
                        allowed: permissionRules[0] == "allow",
                        paths  : permissionRule.paths.map((path: string | RegExp) => {
                            if (!(path instanceof RegExp)) {
                                path = new RegExp("^" + S(path).ensureLeft("/").s + "(/|$)", "i");
                            }
                            return path;
                        })
                    };
            
                    const options: any = permissionRule;
                    delete options["paths"];
                    Object.assign(permissionRuleAllowed, options);
            
                    return permissionRuleAllowed;
                })
                .filter((permissionRuleAllowed: PermissionRuleAllowed) => {
                    return permissionRuleAllowed.paths.length > 0;
                })
                .value();
    }
    
    private validateRules(rules: Array<PermissionRuleAllowed>, req: Request, res: Response, next: NextFunction) {
        async.detectSeries(rules, (rule: PermissionRuleAllowed, callback) => {
            if (rule.methods) {
                if (rule.methods.length > 0 && !_.contains(rule.methods, req.method.toLowerCase())) {
                    return callback(null, false);
                }
            }
            
            if (!_.find(rule.paths, (path: RegExp) => {
                return !!req.originalUrl.match(path);
            })) {
                return callback(null, false);
            }
            
            const keys = _.chain(rule)
                          .keys()
                          .without("allowed", "paths", "methods")
                          .value();
            async.every(keys, (key, callback) => {
                const validator: Function | undefined = this.validators.get(key);
                const ruleValue                                = _.property(key)(rule);
                
                if (!validator) return callback(null, true);
                
                switch (validator.length) {
                    case 0:
                    case 1:
                        return validator.call(this, callback);
                    case 2:
                        return callback(null, !!validator.call(this, req, ruleValue));
                    case 3:
                        return validator.call(this, req, ruleValue, callback);
                    case 4:
                        return validator.call(this, req, res, ruleValue, callback);
                    case 5:
                    default:
                        return validator.call(this, req, res, ruleValue, (result: boolean) => {
                            callback(null, result);
                        }, (err: Error) => {
                            callback(err, false);
                        });
                }
            }, callback);
        }, (err, rule) => {
            if (err) return next(err);
            if (!rule || rule.allowed) return next();
            this.permissionDenied(new PermissionError(403), req, res, next);
        });
    }
}