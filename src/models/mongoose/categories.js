const { Schema, model } = require("mongoose");

const collectionName = "categories";

const collectionSchema = new Schema({
  name: {
    type: Map,
    of: String
  },
  code: String,
  isActive: Boolean
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;