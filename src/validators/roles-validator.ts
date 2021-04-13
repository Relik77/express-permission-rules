import { Request }      from "express-serve-static-core";
import * as _           from "underscore";
import { ValidatorFct } from "./validator.interface";

export const rolesValidator = (userProperty: string, rolenameProperty: string): ValidatorFct<string> => {
    return (req: Request, roles: Array<string>) => {
        if (!Array.isArray(roles)) roles = [roles];
        if (roles.length == 0) return true;
        if (_.contains(roles, "*")) return true;
        
        const user = _.property(userProperty)(req);
        if (!user) return false;
        
        let role_name = user;
        rolenameProperty.split(".").forEach(function (name) {
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
    };
};
