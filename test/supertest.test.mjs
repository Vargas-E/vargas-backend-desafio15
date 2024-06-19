import supertest from "supertest";
import { expect } from "chai";
const requester = supertest("http://localhost:8080");

describe("testing app", () => {
  describe("Test products", () => {
    it("api/products (get test)", async () => {
      const { statusCode, ok, _body } = await requester.get("/api/products/");
      expect(_body).to.have.property("docs");
    });
  });

  describe("Add product", () => {
    it("add product incorrectly (no description)", async () => {
      const newIncorrectProduct = {
        title: "Producto supertest",
        price: 200,
        img: "sin imagen",
        code: "a12343565647",
        stock: 25,
        category: "Kitchen",
        status: true,
        thumbnails: [],
      };
      const { statusCode, ok, _body } = await requester
        .post("/api/products/")
        .send(newIncorrectProduct);

      expect(statusCode).to.equal(500);
      expect(_body).to.have.property("code").that.equals(3);
    });

    it("add product correctly", async () => {
      const newCorrectProduct = {
        title: "Producto supertest",
        description: "Description of supertest product",
        price: 200,
        img: "sin imagen",
        code: "a12343565647",
        stock: 25,
        category: "Kitchen",
        status: true,
        thumbnails: [],
      };
      const { statusCode, ok, _body } = await requester
        .post("/api/products/")
        .send(newCorrectProduct);
      expect(statusCode).to.equal(201);
      expect(_body.response)
        .to.have.property("title")
        .that.equals(newCorrectProduct.title);
    });
  });

  describe("update product", () => {
    it("update product with invalid id", async () => {
      const { statusCode, _body } = await requester
        .put("/api/products/" + "fakeid")
        .send({ description: "new description" });
      expect(statusCode).to.equal(500);
      expect(_body).to.have.property("code").that.equals(3);
    });

    it("update product with valid data and id", async () => {
      const newCorrectProduct = {
        title: "Producto supertest to update ",
        description: "Description of supertest product to update",
        price: 200,
        img: "sin imagen",
        code: "a12343565647234234345345",
        stock: 25,
        category: "Kitchen",
        status: true,
        thumbnails: [],
      };
      const { body } = await requester
        .post("/api/products/")
        .send(newCorrectProduct);
      const id = body.response._id;
      const { statusCode, _body } = await requester
        .put("/api/products/" + id)
        .send({ description: "new description test" });
      expect(statusCode).to.equal(201);
      expect(_body).to.have.property("message").that.includes(id.toString());
    });
  });

  describe("delete product", () => {
    it("delete product with invalid id as query parameter", async () => {
      const { statusCode, _body } = await requester.delete(
        "/api/products/" + "fakeid"
      );
      expect(statusCode).to.equal(500);
      expect(_body).to.have.property("code").that.equals(3);
    });

    it("delete product with valid id", async () => {
      const newCorrectProduct = {
        title: "Producto supertest to delete",
        description: "Description of supertest product to delete",
        price: 200,
        img: "sin imagen",
        code: "a12343565647234234asdads",
        stock: 25,
        category: "Kitchen",
        status: true,
        thumbnails: [],
      };
      const { body } = await requester
        .post("/api/products/")
        .send(newCorrectProduct);
      const id = body.response._id;
      const { statusCode, _body } = await requester.delete(
        "/api/products/" + id
      );
      expect(statusCode).to.equal(200);
    });
  });
});
