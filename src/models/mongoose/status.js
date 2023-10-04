const { Schema, model } = require("mongoose");

const collectionName = "status";

const collectionSchema = new Schema({
  name: String,
  type: {
    type: String,
    enum: ['CART', 'ORDER', 'USER'],
    default: 'CART',
  },
  description: String
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;