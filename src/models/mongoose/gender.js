const { Schema, model } = require("mongoose");

const collectionName = "gender";

const collectionSchema = new Schema({
  name: String,
  description: String
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;