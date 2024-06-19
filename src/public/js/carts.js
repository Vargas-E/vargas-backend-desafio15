const cartContainer = document.getElementById("cartContainer");

const buildCartView = () => {
  if (cart.products.length == 0) {
    const card = document.createElement("div");
    card.classList.add("cartCard");
    card.innerHTML = `<div style="font-size: 1.3rem; text-align:center; margin: auto;">Your Cart is empty!!</div>`;
    cartContainer.appendChild(card);
  } else {
    cart.products.forEach((product) => {
      const productData = product.product;
      const card = document.createElement("div");
      card.classList.add("cartCard");
      card.innerHTML = `<div class="cartCardTextContainer">
          <div>Product: ${productData.title}</div>
          <div>Unit Price: $${productData.price}</div>
          <div>Quantity: ${product.quantity}</div>
          <div>Total of product: ${product.quantity * productData.price}</div>
          </div>
          <div class="cartCardImageContainer"></div>`;
      const icon = document.createElement("button");
      icon.classList.add("deleteButtonCart");
      icon.innerHTML = "DEL";
      icon.addEventListener("click", () => {
        deleteProductFromCart(cart._id, product.product._id);
      });

      const cardAndIcon = document.createElement("div");
      cardAndIcon.classList.add("cardAndIcon");
      cardAndIcon.appendChild(card);
      cardAndIcon.appendChild(icon);
      cartContainer.appendChild(cardAndIcon);
    });
    // total
    const totalPrice = cart.products.reduce((acc, e) => {
      const sum = e.quantity * e.product.price;
      return acc + sum;
    }, 0);

    const total = document.createElement("div");
    total.classList.add("cartTotal");
    total.innerHTML = `Total: $${totalPrice}`;
    cartContainer.appendChild(total);

    // submitButton
    const submitButton = document.createElement("button");
    submitButton.classList.add("button");
    submitButton.classList.add("align");
    submitButton.addEventListener("click", () => {
      finishPurchase(cart._id);
    });
    submitButton.innerHTML = "FINISH PURCHASE";
    cartContainer.appendChild(submitButton);
  }
};

buildCartView();

const deleteProductFromCart = (cartId, prodId) => {
  var url = `http://localhost:8080/api/cart/${cartId}/product/${prodId}`;
  fetch(url, {
    method: "DELETE",
    headers: {
      "Content-Type": "application/json",
    },
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error("Network response was not ok");
      }
      cart = {
        ...cart,
        products: cart.products.filter((e) => e.product._id != prodId),
      };
      cartContainer.innerHTML = "";
      buildCartView();
      // Add a snackbar of product added!
    })
    .catch((error) => {
      console.error("Error fetching data:", error);
    });
};

const finishPurchase = (cartId) => {
  var url = `http://localhost:8080/api/cart/${cartId}/purchase`;
  fetch(url, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
    },
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error("Network response was not ok");
      }
      return response.json();
    })
    .then((data) => {
      const ticket = data.ticket;
      window.location.href = `http://localhost:8080/views/ticket?tId=${ticket._id}`;
    })
    .catch((error) => {
      console.error("Error fetching data:", error);
    });
};
