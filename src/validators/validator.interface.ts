import { Request, Response } from "express-serve-static-core";

export type successCallback = (result: boolean) => void;
export type failCallback = (error: Error) => void;
export type callback = (error: Error | null, result?: boolean) => void;

export type ValidatorFct<T> =
    ((callback: callback) => void)
    | ((req: Request, values: T & Array<T>) => boolean)
    | ((req: Request, values: T & Array<T>, callback: callback) => void)
    | ((req: Request, res: Response, values: T & Array<T>, callback: callback) => void)
    | ((req: Request, res: Response, values: T & Array<T>, successCallback: successCallback, failCallback: failCallback) => void);
