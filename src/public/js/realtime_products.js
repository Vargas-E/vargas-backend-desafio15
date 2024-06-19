const socket = io();

const cancelButton = document.getElementById("btnCancelEdit");
const submitButton = document.getElementById("btnSubmitEdit");
let editedProduct;

console.log("user:", user);

socket.on("products", (data) => {
  if (data === false) {
    Swal.fire({
      title: "El código de producto ya esta en uso",
      confirmButtonColor: "#1A3A3A",
    });
  } else {
    console.log("socketProductos");
    renderProducts(data);
    cancelEdit();
  }
});

// render products array
const renderProducts = (data) => {
  console.log("products:", data);
  const productsContainer = document.getElementById("productsContainer");
  if (!!productsContainer) {
    productsContainer.innerHTML = "";
    let productos;
    console.log("data:", data);
    if (user.rol == "premium" ) {
      productos = data.filter(e => e.owner == user.email)
      console.log("data premium:", productos);
    } else {
      productos = data;
    }

    productos.forEach((product) => {
      const card = document.createElement("div");
      card.classList.add("cartCard");
      card.classList.add("clickable");
      card.addEventListener("click", () => {
        editProduct(product);
      });
      card.innerHTML = `<div class="cartCardTextContainer">
          <div>Product: ${product.title}</div>
          <div>Product code: ${product.code}</div>
          <div>Description: ${product.description}</div>
          <div>Price: ${product.price}</div>
          <div>Current stock: ${product.stock}</div>
          <div>Owner: ${product.owner ?? "admin"}</div>
          </div>
          <div class="cartCardImageContainer"></div>`;
      const icon = document.createElement("button");
      icon.classList.add("deleteButtonCart");
      icon.innerHTML = "DEL";
      icon.addEventListener("click", () => {
        deleteProduct(product._id);
      });

      const cardAndIcon = document.createElement("div");
      cardAndIcon.classList.add("cardAndIcon");
      cardAndIcon.appendChild(card);
      cardAndIcon.appendChild(icon);
      productsContainer.appendChild(cardAndIcon);
    });
  }
};

const deleteProduct = (id) => {
  socket.emit("deleteProduct", id);
};

if (!!document.getElementById("btnSubmitEdit")) {
  document.getElementById("btnSubmitEdit").addEventListener("click", (e) => {
    e.preventDefault();
    addProduct(true);
  });
}

if (!!document.getElementById("btnCancelEdit")) {
  document.getElementById("btnCancelEdit").addEventListener("click", (e) => {
    e.preventDefault();
    cancelEdit();
  });
}

// add
if (!!document.getElementById("btnSend")) {
  document.getElementById("btnSend").addEventListener("click", (e) => {
    e.preventDefault();
    addProduct();
  });
}

const addProduct = (edit) => {
  const newProduct = {
    title: document.getElementById("title").value.trim(),
    description: document.getElementById("description").value.trim(),
    price: parseInt(document.getElementById("price").value),
    img: document.getElementById("img").value.trim(),
    code: document.getElementById("code").value.trim(),
    stock: parseInt(document.getElementById("stock").value),
    category: document.getElementById("category").value.trim(),
    status: document.getElementById("status").value === "true" ? true : false,
    thumbnails: [],
    owner: user.rol === "premium" ? user.email : "admin",
  };
  if (
    Object.keys(newProduct).some((e) =>
      typeof newProduct[e] == "boolean" ? false : !!!newProduct[e]
    )
  ) {
    Swal.fire({
      title: "Error en el form!",
      text: "Alguno de los campos esta vacio, o el precio se asigno como 0. Revisa los campos por favor.",
      confirmButtonColor: "#1A3A3A",
    });
    console.log("error en input");
  } else {
    if (edit == true) {
      socket.emit("updateProduct", {
        productData: newProduct,
        productId: editedProduct["_id"],
      });
      Swal.fire({
        title: `Product with code ${editedProduct.code} updated!`,
        confirmButtonColor: "#1A3A3A",
      });
    } else {
      console.log("addProduct");
      socket.emit("addProduct", newProduct);
      Swal.fire({
        title: "Producto agregado!",
        confirmButtonColor: "#1A3A3A",
      });
    }
  }
};

const editProduct = (product) => {
  editedProduct = product;
  const components = {
    title: document.getElementById("title"),
    price: document.getElementById("price"),
    img: document.getElementById("img"),
    code: document.getElementById("code"),
    stock: document.getElementById("stock"),
    category: document.getElementById("category"),
    status: document.getElementById("status"),
    description: document.getElementById("description"),
  };

  const nameArr = Object.keys(components);
  nameArr.forEach((e) => {
    components[e].value = product[e];
  });

  components.code.disabled = true;
  cancelButton.classList.remove("hidden");
  submitButton.classList.remove("hidden");

  const addButton = document.getElementById("btnSend");
  addButton.classList.add("hidden");
};

const cancelEdit = () => {
  editedProduct = null;
  const components = {
    title: document.getElementById("title"),
    price: document.getElementById("price"),
    img: document.getElementById("img"),
    code: document.getElementById("code"),
    stock: document.getElementById("stock"),
    category: document.getElementById("category"),
    status: document.getElementById("status"),
    description: document.getElementById("description"),
  };

  const nameArr = Object.keys(components);
  nameArr.forEach((e) => {
    e == "status" ? (components[e].value = "true") : (components[e].value = "");
  });

  components.code.disabled = false;
  cancelButton.classList.add("hidden");
  submitButton.classList.add("hidden");
  const addButton = document.getElementById("btnSend");
  addButton.classList.remove("hidden");
};
