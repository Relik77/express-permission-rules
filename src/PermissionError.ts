export class PermissionError extends Error {
    private status: 401 | 403;
    
    constructor(status: 401 | 403 = 403, message: string = "Permission denied") {
        super(message);
        
        this.name   = "PermissionError";
        this.status = status;
    }
}
