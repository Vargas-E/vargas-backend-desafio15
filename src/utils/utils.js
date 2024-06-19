function handleQueryString(queryObject, value) {
  if (value) {
    const queryArr = Object.keys(queryObject).map((e) =>
      e == "page" ? `${e}=${value}` : `${e}=${queryObject[e]}`
    );
    if (!queryObject.page) {
      queryArr.push(`page=${value}`);
    }
    return "/views/products?" + queryArr.join("&");
  }
  return null;
}

function checkNewProduct(product) {
  const fields = ["title", "description", "price", "code", "stock", "category"];
  if (
    fields.every((e) => {
      return !!product[e];
    })
  ) {
    return true;
  }
  return false;
}

function generateTicketCode() {
  var timestamp = Date.now();
  var randomId = timestamp.toString(16);
  var randomNum = Math.floor(Math.random() * 1000); 
  randomId += randomNum.toString().padStart(3, '0'); 
  return randomId;
}




module.exports = { handleQueryString, checkNewProduct, generateTicketCode };
