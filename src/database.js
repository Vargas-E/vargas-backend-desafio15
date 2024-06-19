const mongoose = require("mongoose");
const configObject = require("./config/config.js");
const {mongo_url} = configObject;


class Database {
  static #instance;

  constructor() {
    console.log("start");
    mongoose.connect(mongo_url);
  }

  static getInstance() {
    if (this.#instance) {
      return this.#instance;
    } else {
      this.#instance = new Database();
      console.log("connected to mongo")
      return this.#instance
    }
  }
}

module.exports = Database.getInstance();