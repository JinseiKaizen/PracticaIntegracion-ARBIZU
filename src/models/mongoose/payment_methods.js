const { Schema, model } = require("mongoose");

const collectionName = "payment_methods";

const collectionSchema = new Schema({
  type: {
    type: String,
    enum: ['CUSTOMER', 'PARTNER'],
    default: 'CUSTOMER'
  },
  name: String,
  description: String,
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;