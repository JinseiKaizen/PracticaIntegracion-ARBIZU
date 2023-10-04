const { Schema, model } = require("mongoose");

const collectionName = "care_instructions";

const collectionSchema = new Schema({
  name: {
    type: Map,
    of: String
  },
  code: String,
  icon: {
    type: String,
    default: null
  },
  isActive: Boolean
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;