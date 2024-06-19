const TicketModel = require("../models/ticket.model.js");

class TicketsRepository {

    async createTicket(ticketData) {
        try {
            const newticket = new TicketModel(ticketData);
            await newticket.save();
            return newticket;
          } catch (err) {
            throw new Error(`Error mongo (create ticket): ${err}`);
          }
    }

    async getTicketById(tId) {
      try {
          const ticket = await TicketModel.findById(tId).lean();
          return ticket;
        } catch (err) {
          console.log("err:", err);
          throw new Error(`Error mongo (get ticket): ${err}`);
        }
  }
}

module.exports = TicketsRepository;