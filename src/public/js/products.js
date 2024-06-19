const productsCardsContainer = document.getElementById("productCardsContainer");
const pageButtonsContainer = document.getElementById("pageButtonsContainer");
const prevButton = document.getElementById("prevButton");
const nextButton = document.getElementById("nextButton");
const pageCounter = document.getElementById("pageCounter");


// build products components
products.docs.forEach((product) => {
  let quantity = 1;
  const card = document.createElement("div");
  card.classList.add("productCard");
  card.innerHTML = `<a class="productLink"><div class="productImage" ></div></a><div class="textAndButtonContainer"><div>${product.title}</div><div>$${product.price}</div><div class="quantityContainer"><button id="${product.code}Decrease" class="arrowButton decrease"><</button><div id="${product.code}Counter" class="quantityCounter">${quantity}</div><button id="${product.code}Increase"class="arrowButton increase">></button></div><button class="button fixMargin newButton add"> ADD TO CART </button></div>`;
  productsCardsContainer.appendChild(card);
  const addButton = card.querySelector(".add");
  const decreaseButton = card.querySelector(".decrease");
  const increaseButton = card.querySelector(".increase");
  const cardImageLink = card.querySelector(".productLink");
  cardImageLink.href = `/views/product?id=${product._id}`;
  addButton.addEventListener("click", () => {
    addProductToCart(product._id, quantity);
    quantity = 1;
    const counterElement = document.getElementById(`${product.code}Counter`);
    counterElement.innerText = quantity;
  });
  decreaseButton.addEventListener("click", () => {
    if (quantity > 1) {
      quantity--;
      const counterElement = document.getElementById(`${product.code}Counter`);
      counterElement.innerText = quantity;
    }
    console.log("Decreasing quantity for:", product.title);
  });
  increaseButton.addEventListener("click", () => {
    quantity++;
    const counterElement = document.getElementById(`${product.code}Counter`);
    counterElement.innerText = quantity;
  });
});


// build change page components
prevButton.classList.add("arrowButton");
prevButton.innerHTML = "<";
if (products.hasPrevPage) {
  prevButton.href = products.prevLink;
} else {
  prevButton.classList.add("disabled");
  prevButton.disabled = true;
}

nextButton.classList.add("arrowButton");
nextButton.innerHTML = ">";
if (products.hasNextPage) {
  nextButton.href = products.nextLink;
} else {
  nextButton.classList.add("disabled");
  nextButton.disabled = true;
}

pageCounter.innerHTML = products.page;


// requests
function addProductToCart(prodId, quantity) {
  var url = `http://localhost:8080/api/cart/${user.cart}/product/${prodId}`;
  const product = products.docs.find(e => prodId == e._id);
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
    body: JSON.stringify({quantity: quantity}),
  })
    .then((response) => {
      if (!response.ok) {
        // Add a snackbar of product added!
        throw new Error("Network response was not ok");
      }
      Swal.fire({
        text: `${product.title} added to cart!`,
        confirmButtonColor: "#1A3A3A",
      });
      return response.json();
    })
    .catch((error) => {
      console.error("Error fetching data:", error);
    });
}
