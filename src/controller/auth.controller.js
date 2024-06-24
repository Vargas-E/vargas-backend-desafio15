const jwt = require("jsonwebtoken");
const UserModel = require("../models/user.model");
const UserRepository = require("../repositories/users.repository.js");
const layer = "Controller";
const router = "Auth";
const { generateResetToken } = require("../utils/tokenreset.js");
const { createHash, isValidPassword } = require("../utils/hashbcryp.js");

const userRepository = new UserRepository();
const EmailManager = require("../helpers/email.js");
const emailManager = new EmailManager();

class AuthController {
  async login(req, res) {
    req.logger.info(
      `Request to login. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    try {
      const userForToken = {
        first_name: req.user.first_name,
        last_name: req.user.last_name,
        age: req.user.age,
        email: req.user.email,
        rol: req.user.rol,
        cart: req.user.cart,
      };

      const token = jwt.sign(userForToken, "coderhouse", { expiresIn: "1h" });

      res.cookie("coderCookieToken", token, {
        maxAge: 3600000,
        httpOnly: true,
      });

      const userInDb = userRepository.findByEmail(email);
      user.last_connection = new Date();
      await userInDb.save();
      if (userForToken.rol == "admin") {
        res.redirect("/views/realtime_products");
      } else {
        res.redirect("/views/products");
      }
    } catch (error) {
      req.logger.error(
        `Error while trying login. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(400).send({ error: "Error en el login" });
    }
  }

  async register(req, res) {
    const { first_name, last_name, email, password, age } = req.body;
    req.logger.info(
      `Request to register. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    try {
      const userForToken = {
        first_name: first_name,
        last_name: last_name,
        age: age,
        email: email,
        rol: "user",
        cart: req.user.cart,
      };

      // generamos token JWT
      const token = jwt.sign(userForToken, "coderhouse", { expiresIn: "1h" });

      // mandamos como cookie el token
      res.cookie("coderCookieToken", token, {
        maxAge: 3600000,
        httpOnly: true,
      });

      const userInDb = userRepository.findByEmail(email);
      user.last_connection = new Date();
      await userInDb.save();

      res.redirect("/views/products");
    } catch (error) {
      req.logger.error(
        `Error while trying to register. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).send({ error: "Error al guardar el usuario nuevo" });
    }
  }

  async github(req, res) {}

  async githubcallback(req, res) {
    try {
      const userForToken = {
        first_name: req.user.first_name,
        last_name: req.user.last_name,
        age: req.user.age,
        email: req.user.email,
        rol: req.user.rol,
        cart: req.user.cart,
      };

      const token = jwt.sign(userForToken, "coderhouse", { expiresIn: "1h" });

      res.cookie("coderCookieToken", token, {
        maxAge: 3600000,
        httpOnly: true,
      });

      res.redirect("/views/products");
    } catch (err) {
      console.log("error_:", error);
      res.status(400).send({ error: "Error en el login" });
    }
  }

  async logout(req, res) {
    req.logger.info(
      `Request to log out. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    try {
      res.clearCookie("coderCookieToken");
      res.redirect("/views/login");
    } catch (err) {
      req.logger.error(
        `Error while trying to log out. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(400).send({ error: "Error en el login" });
    }
  }

  async current(req, res) {
    try {
      res.send({ user: req.user });
    } catch (err) {
      console.log("error_:", error);
      res.status(400).send({ error: "Error en el login" });
    }
  }

  async requestPasswordReset(req, res) {
    const { email } = req.body;
    try {
      const user = await UserModel.findOne({ email });
      if (!user) {
        return res.status(404).send("Usuario no encontrado");
      }
      const token = generateResetToken();

      user.resetToken = {
        token: token,
        expiresAt: new Date(Date.now() + 36),
      };
      await user.save();
      await emailManager.enviarCorreoRestablecimiento(
        email,
        user.first_name,
        token
      );
      res.redirect("/views/confirmation_email_sent");
    } catch (error) {
      console.error(error);
      res.status(500).send("Error interno del servidor");
    }
  }

  async resetPassword(req, res) {
    const { email, password, token } = req.body;

    try {
      const user = await UserModel.findOne({ email });
      if (!user) {
        return res.redirect("/views/password?errorCode=0");
      }
      const resetToken = user.resetToken;
      if (!resetToken || resetToken.token !== token) {
        return res.redirect("/views/password?errorCode=1");
      }

      const now = new Date();
      if (now > resetToken.expiresAt) {
        return res.redirect("/views/request_password_reset?errorCode=0");
      }
      if (isValidPassword(password, user)) {
        return res.redirect("/views/password?errorCode=2");
      }

      user.password = createHash(password);
      user.resetToken = undefined;
      await user.save();

      return res.redirect("/views/login");
    } catch (error) {
      console.error(error);
      return res
        .status(500)
        .render("passwordreset", { error: "Error interno del servidor" });
    }
  }

  async changeRolToPremium(req, res) {
    try {
      const { uid } = req.params;
      const user = await UserModel.findById(uid);
      if (!user) {
        return res.status(404).json({ message: "User Not Found" });
      }
      const requiredDocs = ["Identificacion", "Comprobante de domicilio", "Comprobante de estado de cuenta"];
      const userDocuments = user.documents.map(e => e.name);
      const docsExists = requiredDocs.every(e => userDocuments.includes(e))
      if (docsExists) {
        const newRol = user.rol === "user" ? "premium" : "user";
        const updated = await UserModel.findByIdAndUpdate(uid, { rol: newRol });
        res.json(updated);
      } else {
        res.status(400).send("User docs not found. Denied upgrade to premium user");
      }

    } catch (err) {
      req.logger.error(
        `Error while changing role. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(400).send({ error: "Error while changing role" });
    }
  }

  async uploadUserFile(req, res) {
    const { uid } = req.params;
    const uploadedDocuments = req.files;
    try {
      const user = await userRepository.findById(uid);
      if (!user) {
        return res.status(404).send("User not found");
      }
      if (uploadedDocuments) {
        if (uploadedDocuments.document) {
          user.documents = user.documents.concat(
            uploadedDocuments.document.map((doc) => ({
              name: doc.originalname,
              reference: doc.path,
            }))
          );
        }

        if (uploadedDocuments.products) {
          user.documents = user.documents.concat(
            uploadedDocuments.products.map((doc) => ({
              name: doc.originalname,
              reference: doc.path,
            }))
          );
        }

        if (uploadedDocuments.profile) {
          user.documents = user.documents.concat(
            uploadedDocuments.profile.map((doc) => ({
              name: doc.originalname,
              reference: doc.path,
            }))
          );
        }
      }

      //Guardamos los cambios en la base de datos:

      await user.save();

      res.status(200).send("Documentos cargados exitosamente");
    } catch (error) {
      console.log(error);
      res
        .status(500)
        .send(
          "Error interno del servidor, los mosquitos seran cada vez mas grandes"
        );
    }
  }
}

module.exports = AuthController;
