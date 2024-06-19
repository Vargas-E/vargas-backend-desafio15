const generateInfoError = (data, schema) => {
  let message = "Incomplete or invalid data. Required data: ";
  const keys = Object.keys(data);
  let schemaItems = {};
  schema.eachPath(
    (pathName, schemaType) => (schemaItems[pathName] = schemaType.instance)
  );
  Object.keys(schemaItems).forEach((e) => {
    if (e != "_id" && e != "__v") {
      message += `${e}: ${schemaItems[e]}, recieved: ${data[
        e
      ]?.toString()} || `;
    }
  });
  return message;
};

module.exports = {
  generateInfoError,
};
