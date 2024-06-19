const express = require("express");
const router = express.Router();
const passport = require("passport");
const ViewsController = require("../controller/views.controller.js");
const viewsController = new ViewsController();

router.use(express.static("./src/public"));


// Middlewares

// redirect login and register
function authenticateJWT(req, res, next) {
  passport.authenticate("jwt", { session: false }, (err, user, info) => {
    if (user) {
      return res.redirect("/views/products");
    } else {
      return next();
    }
  })(req, res, next);
}

// check rol for admin routes
function adminMiddleware(req, res, next) {
  if (req.user.rol == "admin" || req.user.rol  == "premium") {
    next();
  } else {
    res.redirect("/views/products")
  }
}


// check rol for user routes
function userMiddleware(req, res, next) {
  if (req.user.rol == "user" || req.user.rol  == "premium") {
    next();
  } else {
    res.redirect("/views/realtime_products")
  }
}


function passportAuth(req, res, next) {
  passport.authenticate("jwt", {
    session: false,
    failureRedirect: "/views/login",
  })(req, res, next);
}

// Routes
router.get(
  "/cart",
  passportAuth,
  userMiddleware,
  viewsController.renderCart
);

router.get(
  "/products",
  passportAuth,
  userMiddleware,
  viewsController.renderProducts
);

router.get(
  "/product",
  passportAuth,
  userMiddleware,
  viewsController.renderProduct
);

router.get("/login", authenticateJWT, viewsController.renderLogin);

router.get("/register", authenticateJWT, viewsController.renderRegister);

router.get(
  "/realtime_products",
  passportAuth, adminMiddleware, 
  viewsController.renderRealtimeProducts
);

router.get("/ticket", passportAuth, userMiddleware, viewsController.renderTicket);

router.get("/profile", passportAuth, viewsController.renderProfile)

router.get("/chat", passportAuth, userMiddleware, viewsController.renderChat);

router.get("/test", passportAuth, adminMiddleware, viewsController.test);

router.get("/mocking_products", passportAuth, userMiddleware, viewsController.renderMockingProducts);

router.get("/request_password_reset", viewsController.renderResetPassword)

router.get("/password", viewsController.renderChangePassword);

router.get("/confirmation_email_sent", viewsController.renderConfirmation);


module.exports = router;
