const { faker } = require("@faker-js/faker");

const generateProducts = () => {
  return {
    _id: faker.database.mongodbObjectId(),
    title: faker.commerce.productName(),
    description: faker.commerce.productDescription(),
    price: parseInt(faker.commerce.price()),
    img: faker.image.urlLoremFlickr(),
    code: faker.random.alphaNumeric(10),
    stock: parseInt(faker.string.numeric()),
    category: faker.commerce.department(),
    status: true,
    thumbnails: [faker.image.urlPicsumPhotos()],
  };
};

module.exports = generateProducts;
