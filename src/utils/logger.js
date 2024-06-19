const winston = require("winston");
const program = require("../utils/commander.js");

const { mode } = program.opts();

const niveles = {
  nivel: {
    fatal: 0,
    error: 1,
    warn: 2,
    info: 3,
    http: 4,
    debug: 5,
  },
  colores: {
    fatal: "red",
    error: "yellow",
    warn: "blue",
    info: "green",
    http: "magenta",
    debug: "white",
  },
};

//Creamos un nuevo Logger pero ahora configurando los niveles y los colores a nuestro gusto.
const logger = winston.createLogger({
  levels: niveles.nivel,
  transports: [
    new winston.transports.Console({
      level: mode == "desarrollo" ? "debug" : "info",
      format: winston.format.combine(
        winston.format.colorize({ colors: niveles.colores }),
        winston.format.simple()
      ),
    }),

    //Agregamos un nuevo transporte:
    new winston.transports.File({
      filename: mode == "desarrollo" ? "./error_dev.log" : "./error_prod.log",
      level: "error",
      format: winston.format.simple(),
    }),
  ],
});

//Creamos nuestro propio middleware donde vamos a usar este logger:
const addLogger = (req, res, next) => {
  req.logger = logger;
  req.logger.http(
    `${req.method} en ${req.url} - ${new Date().toLocaleTimeString()}`
  );
  next();
};

module.exports = addLogger;
