const { Schema, model } = require("mongoose");

const collectionName = "cart";

const productItemSchema = new Schema({
  product_id: {
    type: Schema.Types.ObjectId,
    ref: 'products'
  },
  color_id: {
    type: Schema.Types.ObjectId,
    ref: 'colors'
  },
  size: String,
  quantity: Number
});

const collectionSchema = new Schema({
  user_id: {
    type: Schema.Types.ObjectId,
    ref: 'users'
  },
  products: [productItemSchema],
  status_id: {
    type: Schema.Types.ObjectId,
    ref: 'status'
  },
  createdAt: {
    type: Date,
    Default: Date.now()
  },
  updatedAt: {
    type: Date,
    Default: null
  }
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;