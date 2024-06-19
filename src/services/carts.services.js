const CartsRepository = require("../repositories/carts.repository.js");
const ProductsRepository = require("../repositories/products.repository.js");
const TicketsService = require("./tickets.service.js");
const UserModel = require("../models/user.model.js");
const ticketsService = new TicketsService();
const cartsRepository = new CartsRepository();
const productsRepository = new ProductsRepository();
const {generateTicketCode} = require("../utils/utils.js");

class CartsServices {
  async getCartById(id) {
    return await cartsRepository.getCartById(id, true);
  }

  async createCart() {
    return await cartsRepository.createCart();
  }

  async deleteProductsFromCart(cid) {
    const cart = await cartsRepository.getCartById(cid, false);
    if (!cart) {
      throw "Cart to update not found";
    } else {
      cart.products = [];
      await cart.save();
      return cart;
    }
  }

  async addToCart(cid, pid, quantity) {
    const cart = await cartsRepository.getCartById(cid, false);
    if (!cart) {
      throw "Cart to update not found";
    }
    const productExists = cart.products.find(
      (product) => product.product.toString() == pid
    );
    if (productExists) {
      productExists.quantity = productExists.quantity + quantity;
    } else {
      cart.products.push({ product: pid, quantity: quantity });
    }
    cart.markModified("products");
    await cart.save();
    return cart;
  }

  async deleteFromCart(cartId, productId) {
    const cart = await cartsRepository.getCartById(cartId, false);
    if (!cart) {
      throw "Cart to update not found";
    } else {
      cart.products = cart.products.filter((e) => e.product != productId);
      cart.markModified("products");
      await cart.save();
      return cart;
    }
  }

  async addProductsToCart(cartId, products) {
    const cart = await cartsRepository.getCartById(cartId, false);
    if (!cart) {
      throw "Cart to update not found";
    }
    const productsToSend = products.map((e) => {
      return { product: e._id, quantity: e.quantity || 1 };
    });

    productsToSend.forEach((product) => {
      const productExists = cart.products.find(
        (a) => a.product.toString() == product.product
      );
      if (productExists) {
        productExists.quantity = productExists.quantity + product.quantity;
      } else {
        cart.products.push(product);
      }
    });
    cart.markModified("products");
    await cart.save();
    return cart;
  }

  async finishPurchase(cartId) {
    const cart = await cartsRepository.getCartById(cartId, false);
    const user = await UserModel.findOne({ cart: cartId });
    let failedPurchaseProducts = [];
    let leftOverProductsForTicket = [];
    let total = 0;
    for (const cartProduct of cart.products) {
      const product = await productsRepository.getProductByIdNoLean(
        cartProduct.product
      );
      if (product) {
        if (product.stock >= cartProduct.quantity) {
          product.stock = product.stock - cartProduct.quantity;
          total += cartProduct.quantity * product.price;
          product.save();
        } else {
          failedPurchaseProducts.push(cartProduct.product);
          leftOverProductsForTicket.push(cartProduct);
        }
      }
    }
    cart.products = leftOverProductsForTicket;
    cart.markModified("products");
    await cart.save();
    const ticketData = {
      // TODO
      code: generateTicketCode(),
      purchase_datetime: new Date(),
      amount: total,
      purchaser: user.email,
      purchaserId: user._id
    }
    const ticket = await ticketsService.createTicket(ticketData)
    return ticket;
  }
}

module.exports = CartsServices;
