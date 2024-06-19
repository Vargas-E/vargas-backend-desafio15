const express = require("express");
const router = express.Router();
const passport = require("passport");

const ProductsController = require("../controller/products.controller.js");
const productsController = new ProductsController();

router.use(express.static("./src/public"));


router.get("/", productsController.getProducts);

router.get("/:pid", productsController.getProductById);

router.delete("/:pid", productsController.deleteProductById);

router.post("/", productsController.addProduct);

router.put("/:pid", productsController.updateProduct);


module.exports = router;
