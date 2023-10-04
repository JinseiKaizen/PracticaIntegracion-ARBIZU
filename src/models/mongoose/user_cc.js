const { Schema, model } = require("mongoose");

const collectionName = "user_cc";

const collectionSchema = new Schema({
  cvv: Number,
  card_number: Number,
  expiration_date: String,
  billing_address: String,
  card_name: String,
  user_id: {
    type: Schema.Types.ObjectId,
    ref: 'users'
  },
  company_id: {
    type: Schema.Types.ObjectId,
    ref: 'users'
  },
  card_type: String,
  type_e: {
    type: Number,
    default: 1
  }
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;