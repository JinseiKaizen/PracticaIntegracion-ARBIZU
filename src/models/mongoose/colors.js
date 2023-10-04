const { Schema, model } = require("mongoose");

const collectionName = "colors";

const collectionSchema = new Schema({
  name: {
    type: Map,
    of: String
  },
  hex: String
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;