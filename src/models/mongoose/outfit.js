const { Schema, model } = require("mongoose");

const collectionName = "outfit";

const productItemSchema = new Schema({
  product_id: {
    type: Schema.Types.ObjectId,
    ref: 'products'
  },
  order: Number
}, { _id: false });

const collectionSchema = new Schema({
  name: {
    type: Map,
    of: String
  },
  description: String,
  products: [productItemSchema],
  createdAt: {
    type: Date,
    Default: Date.now()
  },
  updatedAt: {
    type: Date,
    Default: null
  },
  deletedAt: {
    type: Date,
    Default: null
  }
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;