import { Request }      from "express-serve-static-core";
import * as _           from "underscore";
import { ValidatorFct } from "./validator.interface";

export const ipsValidator = (): ValidatorFct<string> => {
    return (req: Request, ips: Array<string>) => {
        const clientIp = (req.get("x-forwarded-for") || "").split(",")[0] || req.socket.remoteAddress || "";
        
        if (!Array.isArray(ips)) ips = [ips];
        if (ips.length == 0) return true;
        if (_.contains(ips, "*")) return true; // anyone can access ?
        if (_.contains(ips, clientIp)) return true; // this ip can access ?
        
        return !!_.find(ips, function (ip) {
            let starpos = ip.indexOf("*");
            
            if (starpos < 0) return false;
            return clientIp.substr(0, starpos) == ip.substr(0, starpos);
        });
    };
};
