//Creamos una instancia de socket.io del lado del cliente.

const socket = io();
let userFullname = `${user.first_name} ${user.last_name}`;
const chatBox = document.getElementById("chatBox");

// // sweetAlert
// Swal.fire({
//   title: "Identificate",
//   input: "text",
//   text: "Ingrese tu email para identificarte en el chat",
//   inputValidator: (value) => {
//     return !value && "Necesitas escribir un mail para continuar";
//   },
//   allowOutsideClick: false,
// }).then((result) => {
//   user = result.value;
//   chatBox.focus()
// });

chatBox.addEventListener("keyup", (e) => {
  if (e.key === "Enter") {
    if (chatBox.value.trim().length > 0) {
      socket.emit("newMessage", { user: userFullname, message: chatBox.value });
      chatBox.value = "";
      chatBox.focus();
    }
  }
});

// Initial emit to get the chat
socket.emit("chat", (data) => {});

// on socket.emit "newMessage" we return a socket emit "chat" from the server.
socket.on("chat", (data) => {
  let log = document.getElementById("messagesLogs");
  let mensajes = "";
  if (log) {
    data.forEach((mensaje) => {
      const newMessage =
        mensaje.user == userFullname
          ? `<div class="userMessage"><div class="user">${mensaje.user} dice:</div> <div class="messageText">${mensaje.message}</div> </div>`
          : `<div class="otherMessage"><div class="user">${mensaje.user} dice:</div> <div class="messageText">${mensaje.message}</div> </div>`;
      mensajes = mensajes + newMessage;
      log.innerHTML = mensajes;
    });
    log.scrollTop = log.scrollHeight;
  }
});
