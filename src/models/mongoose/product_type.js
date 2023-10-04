const { Schema, model } = require("mongoose");

const collectionName = "product_type";

const collectionSchema = new Schema({
  name: String,
  description: String
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;