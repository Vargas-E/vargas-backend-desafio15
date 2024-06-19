const CartsServices = require("../services/carts.services.js");
const cartsServices = new CartsServices();

const ProductsServices = require("../services/products.services.js");
const productsServices = new ProductsServices();

const TicketsService = require("../services/tickets.service.js");
const ticketsService = new TicketsService();

const ChatService = require("../services/chat.services.js");
const chatService = new ChatService();

const socket = require("socket.io");
const UserDto = require("../dto/user.dto.js");

const generateProducts = require("../utils/faker.js");

const layer = "Controller";
const router = "Views";

class ViewsController {
  async renderCart(req, res) {
    req.logger.info(
      `Request to render cart page. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    const user = req.user;
    const dtoUser = new UserDto(user);
    try {
      const userCartId = req.user.cart;
      req.logger.info(
        `Getting cartData. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
      );
      const newCart = await cartsServices.getCartById(userCartId, true);
      req.logger.info(
        `Rendering cart page... Layer:${layer}, Router: ${router}, Date: ${new Date()}`
      );
      res.render("cart", {
        cart: JSON.stringify(newCart),
        active: { cart: true },
        user: dtoUser,
      });
    } catch (err) {
      req.logger.error(
        `Error while rendering products page. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ message: "Server problems" });
    }
  }

  async renderProducts(req, res) {
    req.logger.info(
      `Request to render products page. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    const user = req.user;
    const dtoUser = new UserDto(user);
    try {
      req.logger.info(
        `Getting products data. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
      );
      const products = await productsServices.getProducts(req.query);
      req.logger.info(
        `Rendering products page...  Layer:${layer}, Router: ${router}, Date: ${new Date()}`
      );
      res.render("products", {
        products: products,
        active: { products: true },
        user: dtoUser,
      });
    } catch (err) {
      req.logger.error(
        `Error while rendering products page. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ error: err });
    }
  }

  async renderProduct(req, res) {
    req.logger.info(
      `Request to render product page. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );

    const id = req.query.id;
    const user = req.user;
    const dtoUser = new UserDto(user);
    try {
      req.logger.info(
        `Getting product data. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
      );
      const product = await productsServices.getProductById(id);
      req.logger.info(
        `Rendering product page...  Layer:${layer}, Router: ${router}, Date: ${new Date()}`
      );
      res.render("product", {
        product: product,
        user: dtoUser,
      });
    } catch (err) {
      req.logger.error(
        `Error while rendering product page. Layer:${layer}, Router: ${router}, Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ error: err });
    }
  }

  async renderLogin(req, res) {
    req.logger.info(
      `Request to render login page. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    const error = req.query.error;
    try {
      if (error != undefined) {
        res.render("login", { error: true });
      } else {
        res.render("login");
      }
    } catch (err) {
      req.logger.error(
        `Error while rendering login page. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ error: err });
    }
  }

  async renderRegister(req, res) {
    req.logger.info(
      `Request to render register page. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    const error = req.query.error;
    try {
      if (req.user) {
        return res.redirect("/views/products");
      }
      if (error != undefined) {
        res.render("register", { error: true });
      } else {
        res.render("register");
      }
    } catch (err) {
      req.logger.error(
        `Error while rendering register page. Layer:${layer}, Router: ${router}, Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ error: err });
    }
  }

  async renderRealtimeProducts(req, res) {
    req.logger.info(
      `Request to render realtimeproducts page. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    var httpServer = req.httpServer;
    const io = socket(httpServer);
    const user = req.user;
    const dtoUser = new UserDto(user);
    try {
      req.logger.info(
        `Opening socket and rendering realtimeproducs page. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
      );
      io.on("connection", async (socket) => {
        socket.emit("products", await productsServices.getProductsNoPaginate());

        socket.on("deleteProduct", async (id) => {
          await productsServices.deleteProductById(id);
          io.sockets.emit(
            "products",
            await productsServices.getProductsNoPaginate()
          );
        });

        socket.on("addProduct", async (newProduct) => {
          const addResponse = await productsServices.addProduct(newProduct);
          if (addResponse == false) {
            console.log("server product already Exists");
            io.sockets.emit("products", false);
          } else {
            await new Promise((resolve) => {
              setTimeout(resolve, 300);
            });
            const products = await productsServices.getProductsNoPaginate();
            console.log("products in server:", products);
            io.sockets.emit("products", products);
          }
        });

        socket.on("updateProduct", async (args) => {
          const updateResponse = await productsServices.updateProduct(
            args.productId,
            args.productData
          );
          io.sockets.emit(
            "products",
            await productsServices.getProductsNoPaginate()
          );
        });
      });
      res.render("realtimeproducts", {
        user: dtoUser,
        active: { realtime_products: true },
      });
    } catch (err) {
      req.logger.error(
        `Error while rendering realtimeproducts page. Layer:${layer}, Router: ${router}, Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ error: "server error" });
    }
  }

  async renderProfile(req, res) {
    req.logger.info(
      `Request to render profile page. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    try {
      const user = req.user;
      const dtoUser = new UserDto(user);
      res.render("profile", { user: dtoUser, active: { profile: true } });
    } catch (err) {
      req.logger.error(
        `Error while rendering profile page. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
      );
      res.status(500).json({ error: "server error" });
    }
  }

  async renderTicket(req, res) {
    req.logger.info(
      `Request to render ticket page. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    const { tId } = req.query;
    try {
      const user = req.user;
      const dtoUser = new UserDto(user);
      const ticket = await ticketsService.getTicketById(tId);
      console.log("ticket en renderTicket:", ticket);
      res.render("ticket", { user: dtoUser, ticket: ticket });
    } catch (err) {
      req.logger.error(
        `Error while rendering ticket page. Layer:${layer}, Router: ${router}, Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ error: "server error" });
    }
  }

  async renderChat(req, res) {
    req.logger.info(
      `Request to render chat page. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    var httpServer = req.httpServer;
    const io = socket(httpServer);
    const user = req.user;
    const dtoUser = new UserDto(user);
    try {
      req.logger.info(
        `Opening socket and rendering chat page. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
      );
      io.on("connection", (socket) => {
        console.log("Initiating CHAT websocket connection");
        socket.on("chat", async () => {
          const chat = await chatService.getChat();
          io.emit("chat", chat);
        });

        socket.on("newMessage", async (newMessage) => {
          await chatService.addMessageToChat(newMessage);
          const newChat = await chatService.getChat();
          io.emit("chat", newChat);
        });
      });

      res.render("chat", { active: { chat: true }, user: dtoUser });
    } catch (err) {
      req.logger.error(
        `Error while rendering chat page. Layer:${layer}, Router: ${router}, Error: ${err}, Date: ${new Date()}`
      );

      res.status(500).json({ error: "server error" });
    }
  }

  async test(req, res) {
    res.render("test", { user: req.user, active: { test: true } });
  }

  async renderMockingProducts(req, res) {
    req.logger.info(
      `Request to render mock products page. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );

    const user = req.user;
    const dtoUser = new UserDto(user);
    try {
      const products = [];
      for (let i = 0; i < 100; i++) {
        products.push(generateProducts());
      }
      res.render("mocking_products", {
        products: products,
        active: { mocking_products: true },
        user: dtoUser,
      });
    } catch (err) {
      req.logger.error(
        `Error while rendering chat page. Layer:${layer}, Router: ${router}, Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json({ error: err });
    }
  }

  async renderResetPassword(req, res) {
    const { errorCode } = req.query;
    let error;
    if (errorCode) {
      switch (errorCode) {
        case "0":
          error = "Reset code has expired";
          break;
        default:
          error = "Unknown error";
      }
    }
    res.render("form_password_reset", { error });
  }

  async renderChangePassword(req, res) {
    const { errorCode } = req.query;
    let error;
    if (errorCode) {
      switch (errorCode) {
        case "0":
          error = "User not found";
          break;
        case "1":
          error = "Reset code is incorrect";
          break;
        case "2":
          error = "New password can't be the same as the old one";
          break;
        default:
          error = "Unknown error";
      }
    }
    res.render("submit_password_reset", { error });
  }

  async renderConfirmation(req, res) {
    res.render("confirmation_email_sent");
  }
}

module.exports = ViewsController;
