const CartsServices = require("../services/carts.services.js");
const cartsServices = new CartsServices();

const layer = "Controller";
const router = "Cart";

class CartsController {
  async getCartById(req, res) {
    req.logger.info(
      `Request to get cart by id. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    const { cid } = req.params;
    try {
      const cart = await cartsServices.getCartById(cid);
      if (cart) {
        res.status(200).json(cart);
      } else {
        res.status(404).json({ message: `Cart with id ${cid} not found` });
      }
    } catch (err) {
      req.logger.error(
        `Error while getting cart by id. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ message: "Server problems" });
    }
  }

  async createCart(req, res) {
    req.logger.info(
      `Request to create cart. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    try {
      const newCart = await cartsServices.createCart();
      res.json({ message: `Cart created with id ${newCart._id}` });
    } catch (err) {
      req.logger.error(
        `Error while creating cart by id. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ message: "Server problems" });
    }
  }

  async deleteProductsFromCart(req, res) {
    req.logger.info(
      `Request to delete product from cart. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    try {
      const { cid } = req.params;
      if (cid) {
        const status = await cartsServices.deleteProductsFromCart(cid);
        // const status = await cartManagerDb.deleteAllProductsFromCart(cid);
        res.status(200).json({ messsage: status });
      }
    } catch (err) {
      req.logger.error(
        `Error while deleting product from cart. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ message: err });
    }
  }

  async addToCart(req, res) {
    req.logger.info(
      `Request to add product from cart. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    try {
      const quantity = req.body.quantity;
      const { cid, pid } = req.params;
      if (cid && pid) {
        const status = await cartsServices.addToCart(cid, pid, quantity);
        res.status(200).json({ messsage: status });
      }
    } catch (err) {
      req.logger.error(
        `Error while adding product from cart. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ message: err });
    }
  }

  async deleteFromCart(req, res) {
    req.logger.info(
      `Request to delete product from cart. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    try {
      const { cid, pid } = req.params;
      if (cid && pid) {
        const status = await cartsServices.deleteFromCart(cid, pid);
        res.status(200).json({ messsage: status });
      }
    } catch (err) {
      req.logger.error(
        `Error while deleting product from cart. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ message: err });
    }
  }

  async addProductsToCart(req, res) {
    req.logger.info(
      `Request to add products from cart. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    try {
      const { cid } = req.params;
      if (cid) {
        const products = req.body;
        const status = await cartsServices.addProductsToCart(cid, products);
        res.status(200).json({ messsage: status });
      }
    } catch (err) {
      req.logger.error(
        `Error while adding products from cart. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ message: err });
    }
  }

  async finishPurchase(req, res) {
    req.logger.info(
      `Request to finish purchase. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    try {
      const cartId = req.params.cid;
      const response = await cartsServices.finishPurchase(cartId);
      res.status(200).json({ ticket: response });
    } catch (err) {
      req.logger.error(
        `Error while finishing purchase. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ message: err });
    }
  }
}

module.exports = CartsController;
