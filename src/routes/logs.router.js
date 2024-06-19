const express = require("express");
const router = express.Router();


router.get("/", (req, res) => {
    req.logger.fatal("fatal logger example"); 
    req.logger.error("error logger example"); 
    req.logger.warn("warn logger example");
    req.logger.info("info logger example");
    req.logger.http("http logger example");
    req.logger.debug("debug logger example");
    res.send("Logs generated!!");
})

module.exports = router;