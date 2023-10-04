const { Schema, model } = require("mongoose");

const collectionName = "delivery_options";

const collectionSchema = new Schema({
  name: {
    type: String,
    enum: ['STANDARD', 'EXPRESS', 'SAME_DAY'],
    default: 'STANDARD',
    unique: true
  },
  description: String,
  charge: {
    type: Map,
    of: Schema.Types.Decimal128
  },
  type: {
    type: String,
    enum: ['PORCENTAGE', 'SUM'],
    default: 'PORCENTAGE'
  }
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;