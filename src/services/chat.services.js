const ChatRepository = require("../repositories/chat.repository.js");
const chatRepository = new ChatRepository();

class ChatsService {
  async getChat() {
    const chat = await chatRepository.getChat()
    return chat;
  }

  async addMessageToChat(newMessage) {
    const response = await chatRepository.addMessageToChat(newMessage);
    return response;
  }
}

module.exports = ChatsService;
