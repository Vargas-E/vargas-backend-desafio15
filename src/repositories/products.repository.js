const {ProductModel} = require("../models/product.model");

class ProductsRepository {
  async getProducts(query, args) {
    const products = await ProductModel.paginate(query, args);
    return products;
  }

  async getProductsNoPaginate() {
    const products = await ProductModel.find();
    return products;
  }

  async getProductById(id) {
    const product = await ProductModel.findById(id).lean();
    return product;
  }

  async getProductByIdNoLean(id) {
    const product = await ProductModel.findById(id);
    return product;
  }

  async getProductByCode(code) {
    const product = await ProductModel.findOne({ code: code });
    return product;
  }

  async deleteProductById(id) {
    const deleteProduct = await ProductModel.findByIdAndDelete(id);
    return deleteProduct;
  }

  async addProduct(newProduct) {
    const product = new ProductModel({
      ...newProduct,
      status: true,
      thumbnails: newProduct.thumbnails || [],
    });
    product.save();
    return product;
  }

  async updateProduct(id, productData) {
    const newProduct = await ProductModel.findByIdAndUpdate(id, productData);
    console.log("newProduct:", newProduct)
    return newProduct;
  }
}

module.exports = ProductsRepository;
