import { Request, Response }                                     from "express-serve-static-core";
import * as _                                                    from "underscore";
import { callback, failCallback, successCallback, ValidatorFct } from "./validator.interface";

export type ExpressionFunctionValidator =
    ((user: any) => boolean)
    & ((user: any, callback: callback) => void)
    & ((req: Request, res: Response, user: any) => boolean)
    & ((req: Request, res: Response, user: any, callback: callback) => void)
    & ((req: Request, res: Response, user: any, successCallback: successCallback, failCallback: failCallback) => void);

export const expressionValidator = (userProperty: string): ValidatorFct<string> => {
    return (req: Request, res: Response, expression: string | ExpressionFunctionValidator, callback: callback) => {
        if (typeof expression == "string") expression = new Function("req", "res", "user", expression) as ExpressionFunctionValidator;
        if (typeof expression != "function") return callback(null, false);
        
        const user = _.property(userProperty)(req);
        switch (expression.length) {
            case 0:
            case 1:
                return callback(null, !!expression(user));
            case 2:
                return expression(user, callback);
            case 3:
                return callback(null, !!expression(req, res, user));
            case 4:
                return expression(req, res, user, callback);
            case 5:
            default:
                return expression(req, res, user, (result: boolean) => {
                    callback(null, result);
                }, (err: Error) => {
                    callback(err, false);
                });
        }
    };
};
