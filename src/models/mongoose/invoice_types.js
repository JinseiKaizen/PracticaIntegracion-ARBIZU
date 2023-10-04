const { Schema, model } = require("mongoose");

const collectionName = "invoice_type";

const collectionSchema = new Schema({
  name: {
    type: String,
    enum: ['CUSTOMER', 'PARTNER'],
    default: 'CUSTOMER',
    unique: true
  },
  description: String
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;