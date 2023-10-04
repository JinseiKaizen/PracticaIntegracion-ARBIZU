const { Schema, model } = require("mongoose");

const collectionName = "payment_status";

const collectionSchema = new Schema({
  name: {
    type: String,
    enum: ['PENDING', 'PAID', 'REFUND', 'DELETED'],
    default: 'PENDING',
    unique: true
  },
  description: String
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;