const mongoose = require("mongoose");


const ticketSchema = new mongoose.Schema({
    code: {
        type: String
    },
    purchase_datetime: {
        type: Date
    },
    amount: {
        type: Number
    },
    purchaser: {
        type: String
    },
    purchaserId: {
       type: mongoose.Schema.Types.ObjectId,
    }
});

const TicketModel = mongoose.model("tickets", ticketSchema);

module.exports = TicketModel;