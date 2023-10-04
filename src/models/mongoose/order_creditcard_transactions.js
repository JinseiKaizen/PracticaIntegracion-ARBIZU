const { Schema, model } = require("mongoose");

const collectionName = "order_creditcard_transaction";

const collectionSchema = new Schema({
  order_id: {
    type: Schema.Types.ObjectId,
    ref: 'order'
  },
  user_credit_card_id: {
    type: Schema.Types.ObjectId,
    ref: 'user_cc'
  },
  transaction_id: String,
  response_code: String,
  message_code: String,
  description_transaction: String,
  api_json_response: String,
  createdAt: {
    type: Date,
    Default: Date.now()
  },
  updatedAt: {
    type: Date,
    Default: null
  },
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;