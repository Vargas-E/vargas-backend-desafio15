const CartModel = require("../models/cart.model.js");

class CartsRepository {
  async getCartById(id, populate) {
    try {
      let cart;
      if (populate) {
        cart = await CartModel.findById(id).populate("products.product").exec();
      } else {
        cart = await CartModel.findById(id);
      }
      if (!cart) {
        console.log("No se encontro el carrito por id");
        throw "Cart not found";
      }
      return cart;
    } catch (err) {
      throw new Error(`Error mongo (get cart): ${err}`);
    }
  }

  async createCart() {
    try {
      const newCart = new CartModel({ products: [] });
      await newCart.save();
      return newCart;
    } catch (err) {
      throw new Error(`Error mongo (create cart): ${err}`);
    }
  }

  async updateCart(cart) {
    try {
      cart.products = cart.products.filter((e) => e.product != productId);
      cart.markModified("products");
      await cart.save();
      return cart;
    } catch (err) {
      throw new Error(`Error mongo (create cart): ${err}`);
    }
  }
}

module.exports = CartsRepository;
