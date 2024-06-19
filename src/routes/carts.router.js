const express = require("express");
const router = express.Router();
const CartsController = require("../controller/carts.controller.js");
const cartsController = new CartsController();

router.use(express.static("./src/public"));


// TEST THESE
router.get("/:cid", cartsController.getCartById);

router.post("/", cartsController.createCart);

router.delete("/:cid", cartsController.deleteProductsFromCart);

router.put("/:cid/product/:pid", cartsController.addToCart);

router.delete("/:cid/product/:pid", cartsController.deleteFromCart);

router.put("/:cid", cartsController.addProductsToCart);

router.get("/:cid/purchase", cartsController.finishPurchase);

module.exports = router;
