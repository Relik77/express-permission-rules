import { ExpressionFunctionValidator } from "./validators/expression-validator";

export declare namespace expressPermissionRules {
    type Method = "get" | "post" | "put" | "delete" | "patch" | "options" | "head";
    
    interface PermissionRulesOptions {
        redirectUrl?: string;
        userProperty?: string;
        rolenameProperty?: string;
        loginProperty?: string;
    }
    
    interface PermissionRule {
        paths: Array<string | RegExp>;
        methods?: Array<Method>;
        users?: Array<"*" | "?" | "@" | string>;
        expression?: string | ExpressionFunctionValidator;
        ips?: Array<string>;
        roles?: Array<string>;
    }
    
    type PermissionRules = ["allow" | "deny", PermissionRule];
}
