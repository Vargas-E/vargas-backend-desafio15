const ProductsService = require("../services/products.services.js");
const productsService = new ProductsService();

const { EErrors } = require("../utils/errors/enums.js");
const CustomError = require("../utils/errors/custom-error.js");

const mongoose = require("mongoose");

function isValidObjectId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}

const layer = "Controller";
const router = "Products";

class ProductController {
  async getProducts(req, res) {
    req.logger.info(
      `Request to get products. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    try {
      const products = await productsService.getProducts(req.query);
      res.status(200).json(products);
    } catch (err) {
      req.logger.error(
        `Error while getting products. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json(err);
    }
  }

  async getProductById(req, res) {
    const { pid } = req.params;
    try {
      req.logger.info(
        `Request to get product by id. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
      );
      if (!isValidObjectId(pid)) {
        req.logger.warn(
          `Invalid product. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
        );
        throw CustomError.crearError({
          name: "get product by id",
          cause: `Id not valid`,
          message: `Valid id Paramater needed as param`,
          code: EErrors.MISSING_VALUE,
        });
      } else {
        const product = await productsService.getProductById(pid);
        res.status(200).json(product);
      }
    } catch (err) {
      req.logger.error(
        `Error while getting product by id. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json(err);
    }
  }

  async deleteProductById(req, res) {
    const { pid } = req.params;
    try {
      req.logger.info(
        `Request to delete product by id. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
      );
      if (!isValidObjectId(pid)) {
        req.logger.warn(
          `Invalid product. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
        );
        throw CustomError.crearError({
          name: "Delete product by id",
          cause: `Invalid id`,
          message: `Valid id Paramater needed as param`,
          code: EErrors.MISSING_VALUE,
        });
      } else {
        const product = await productsService.deleteProductById(pid);
        res.status(200).json({ message: `Product with id ${pid} deleted` });
      }
    } catch (err) {
      req.logger.error(
        `Error while deleting product by id. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json(err);
    }
  }

  async addProduct(req, res) {
    req.logger.info(
      `Request to add product. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    const newProduct = req.body;
    try {
      const response = await productsService.addProduct(newProduct);
      res.status(201).json({ response });
    } catch (err) {
      req.logger.error(
        `Error while adding product by id. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json(err);
    }
  }

  async updateProduct(req, res) {
    req.logger.info(
      `Request to update product. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
    );
    const { pid } = req.params;
    const newProductValues = req.body;
    try {
      if (
        isValidObjectId(pid) &&
        !(Object.keys(newProductValues).length === 0)
      ) {
        await productsService.updateProduct(pid, newProductValues);
        res.status(201).json({ message: `Product with id ${pid} updated` });
      } else {
        req.logger.warn(
          `Invalid values. Layer:${layer}, Router: ${router}, Date: ${new Date()}`
        );
        throw CustomError.crearError({
          name: "Update product by id",
          cause: `Missing values. Required fields to update in body and productId: String as param`,
          message: `Issue while trying to update product`,
          code: EErrors.MISSING_VALUE,
        });
      }
    } catch (err) {
      req.logger.error(
        `Error while updating product by id. Layer:${layer}, Router: ${router}. Error: ${err}, Date: ${new Date()}`
      );
      res.status(500).json(err);
    }
  }

  // async renderResetPassword(req, res) {
  //   res.render("passwordreset");
  // }

  // async renderCambioPassword(req, res) {
  //   res.render("passwordcambio");
  // }

  // async renderConfirmacion(req, res) {
  //   res.render("confirmacion-envio");
  // }
}

module.exports = ProductController;
