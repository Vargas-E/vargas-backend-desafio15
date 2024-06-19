class CustomError {
    static crearError({name = "Error", cause = "Desconocido", message, code = 1}){
        const error = new Error(); 
        error.name = name;
        error.cause = cause;
        error.code = code;
        error.message = message;
        throw error; 
    }

}

module.exports = CustomError; 