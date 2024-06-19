const addButton = document.getElementById("addToCart");
const decreaseButton = document.getElementById("decreaseButton");
const increaseButton = document.getElementById("increaseButton");
const counterElement = document.getElementById("counter");

let quantity = 1;

addButton.addEventListener("click", () => {
  addProductToCart(product._id, quantity);
  quantity = 1;
  const counterElement = document.getElementById(`counter`);
  counterElement.innerText = quantity;
});
decreaseButton.addEventListener("click", () => {
  if (quantity > 1) {
    quantity--;
    const counterElement = document.getElementById(`counter`);
    counterElement.innerText = quantity;
  }
});
increaseButton.addEventListener("click", () => {
  quantity++;
  const counterElement = document.getElementById(`counter`);
  counterElement.innerText = quantity;
});

function addProductToCart(prodId, quantity) {
  var url = `http://localhost:8080/api/cart/${user.cart}/product/${prodId}`;
  if (product && product.owner == user.email) {
    Swal.fire({
      title: "This product is owned by you.",
      text: "You are not allowed to buy products you added yourself as a premium user.",
      confirmButtonColor: "#1A3A3A",
    });
    return;
  }
  fetch(url, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ quantity: quantity }),
  })
    .then((response) => {
      if (!response.ok) {
        // Add a snackbar of product added!
        throw new Error("Network response was not ok");
      }
      return response.json();
    })
    .catch((error) => {
      console.error("Error fetching data:", error);
    });
}
