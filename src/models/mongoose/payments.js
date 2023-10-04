const { Schema, model } = require("mongoose");

const collectionName = "payments";

const collectionSchema = new Schema({
  amount: Schema.Types.Decimal128,
  transaction_id: String,
  from: String,
  to: String,
  payment_date: Date,
  comments: String,
  order_id: {
    type: Schema.Types.ObjectId,
    ref: 'order'
  },
  user_id: {
    type: Schema.Types.ObjectId,
    ref: 'users'
  },
  payment_method_id: {
    type: Schema.Types.ObjectId,
    ref: 'payment_methods'
  },
  payment_status_id: {
    type: Schema.Types.ObjectId,
    ref: 'payment_status'
  },
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