const TicketsRepository = require("../repositories/tickets.repository.js");
const ticketsRepository = new TicketsRepository();

class TicketsService {

    async createTicket(ticketData) {
        const ticket = await ticketsRepository.createTicket(ticketData);
        return ticket;
    }

    async getTicketById(tId) {
        const ticket = await ticketsRepository.getTicketById(tId);
        return ticket
    }
}

module.exports = TicketsService;