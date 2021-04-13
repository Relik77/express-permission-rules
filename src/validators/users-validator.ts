import { Request }      from "express-serve-static-core";
import * as _           from "underscore";
import { ValidatorFct } from "./validator.interface";

export const userValidator = (userProperty: string, loginProperty: string): ValidatorFct<string> => {
    return (req: Request, users: Array<string>) => {
        if (!Array.isArray(users)) users = [users];
        if (users.length == 0) return true;
        if (_.contains(users, "*")) return true; // anyone can access ?
        
        const user = _.property(userProperty)(req);
        if (_.contains(users, "?") && !user) return true; // guest can access ?
        if (_.contains(users, "@") && user) return true; // guest can access ?
        if (user && _.contains(users, _.property(loginProperty)(user))) return true; // this member can access ?
        
        return false;
    };
};
