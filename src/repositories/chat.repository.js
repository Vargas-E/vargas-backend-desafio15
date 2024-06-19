const ChatModel = require("../models/chat.model.js");

class ChatRepository {
  
  async getChat() {
    try {
      const chat = await ChatModel.find();
      return chat;
    } catch (err) {
      console.log("Error al actualizar chat:", err);
      throw err;
    }
  }

  async addMessageToChat(newMessage) {
    try {
      const newChatMessage = new ChatModel(newMessage);
      const save = await newChatMessage.save();
      if (!save) {
        console.log("No se pudo agregar mensaje");
      }
      console.log("Chat actualizado");
      return newMessage;
    } catch (err) {
      console.log("Error al actualizar chat:", err);
      throw err;
    }
  }
}

module.exports = ChatRepository;
