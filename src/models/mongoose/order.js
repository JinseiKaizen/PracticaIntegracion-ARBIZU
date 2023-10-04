const { Schema, model } = require("mongoose");

const collectionName = "order";

const messageSchema = new Schema({
  from: {
    type: String,
    enum: ['CLIENT', 'COMPANY'],
    default: 'CLIENT'
  },
  to: {
    type: String,
    enum: ['CLIENT', 'COMPANY'],
    default: 'COMPANY'
  },
  text: String,
  isActive: Boolean,
  seen: {
    type: Boolean,
    Default: false
  }
}, { _id: false });


const collectionSchema = new Schema({
  user_id: {
    type: Schema.Types.ObjectId,
    ref: 'users'
  },
  cart_id: {
    type: Schema.Types.ObjectId,
    ref: 'cart'
  },
  estimated_delivery_date: Date,
  picked_up_at: Date,
  delivered_at: Date,
  customer_messages: [messageSchema],
  verified: Boolean,
  status_id: {
    type: Schema.Types.ObjectId,
    ref: 'status'
  },
  payment_method_id: {
    type: Schema.Types.ObjectId,
    ref: 'method_payment'
  },
  payment_status_id: {
    type: Schema.Types.ObjectId,
    ref: 'payment_status'
  },
  delivery_option_id: {
    type: Schema.Types.ObjectId,
    ref: 'delivery_options'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  cancel_reason: String,
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