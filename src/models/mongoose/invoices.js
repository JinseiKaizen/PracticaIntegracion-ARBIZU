const { Schema, model } = require("mongoose");

const collectionName = "invoices";

const collectionSchema = new Schema({
  amount: Schema.Types.Decimal128,
  invoice_url: String,
  order_id: {
    type: Schema.Types.ObjectId,
    ref: 'order'
  },
  invoice_type_id: {
    type: Schema.Types.ObjectId,
    ref: 'invoice_type'
  },
  archived: Boolean,
  email_sent: Boolean,
  is_paid: Boolean,
  paid_at: {
    type: Date,
    Default: Date.now()
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