const ProductsRepository = require("../repositories/products.repository.js");
const productsRepository = new ProductsRepository();
const { handleQueryString, checkNewProduct } = require("../utils/utils.js");
const { productSchema } = require("../models/product.model.js");

const { generateInfoError } = require("../utils/errors/info.js");
const { EErrors } = require("../utils/errors/enums.js");
const CustomError = require("../utils/errors/custom-error.js");

class ProductsService {
  async getProducts(queryObject) {
    const limit = queryObject.limit;
    const page = queryObject.page;
    const sort = queryObject.sort;
    const query = queryObject.query;
    let products;
    let args = {
      limit: limit || 10,
      page: page || 1,
      lean: true,
    };
    if (sort) {
      args.sort = { price: sort };
    }
    if (query) {
      products = await productsRepository.getProducts(
        { category: query },
        args
      );
    } else {
      products = await productsRepository.getProducts({}, args);
    }

    if (!products) {
      throw CustomError.crearError({
        name: "Get products",
        cause: `Db Error`,
        message: "Issue while fetching products from db",
        code: EErrors.BD_ERROR,
      });
    }

    products.prevLink = handleQueryString(queryObject, products.prevPage);
    products.nextLink = handleQueryString(queryObject, products.nextPage);
    return products;
  }

  async getProductsNoPaginate() {
    const products = await productsRepository.getProductsNoPaginate();
    if (!products) {
      throw CustomError.crearError({
        name: "Get products",
        cause: `Db Error`,
        message: "Issue while fetching products from db",
        code: EErrors.BD_ERROR,
      });
    }
    return products;
  }

  async getProductById(id) {
    const product = await productsRepository.getProductById(id);
    if (!product) {
      throw CustomError.crearError({
        name: "Get product by id",
        cause: `Product wit id ${id} not found in db`,
        message: "Product not found in db",
        code: EErrors.NOT_FOUND,
      });
    }
    console.log("Producto encontrado");
    return product;
  }

  async deleteProductById(id) {
    const response = await productsRepository.deleteProductById(id);
    if (!response) {
      throw CustomError.crearError({
        name: "Delete product by id",
        cause: `Product with id ${id} not found`,
        message: `Issue while trying to delete product with id ${id}`,
        code: EErrors.NOT_FOUND,
      });
    }
    return response;
  }

  async addProduct(newProduct) {
    if (!checkNewProduct(newProduct)) {
      throw CustomError.crearError({
        name: "Create new product",
        cause: generateInfoError(newProduct, productSchema),
        message: "Error while trying to create a product",
        code: EErrors.MISSING_VALUE,
      });
    } else {
      const productExists = await productsRepository.getProductByCode(
        newProduct.code
      );
      if (productExists) {
        return false;
      }
      const product = await productsRepository.addProduct(newProduct);
      return product;
    }
  }

  async updateProduct(id, productData) {
    const response = await productsRepository.updateProduct(id, productData);
    if (!response) {
      throw CustomError.crearError({
        name: "Update new product",
        cause: `Product with id ${id} not found in db`,
        message: "Error while trying to update a product",
        code: EErrors.MISSING_VALUE,
      });
    } else {
      return response;
    }
  }
}

module.exports = ProductsService;
