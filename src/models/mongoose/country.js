const { Schema, model } = require("mongoose");

const collectionName = "countries";

const collectionSchema = new Schema({
  name: {
    type: Map,
    of: String
  },
  code: String
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;