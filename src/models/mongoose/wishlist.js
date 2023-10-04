const { Schema, model } = require("mongoose");

const collectionName = "wishlist";

const collectionSchema = new Schema({
  user_id: {
    type: Schema.Types.ObjectId,
    ref: 'users'
  },
  products: [{
    type: Schema.Types.ObjectId,
    ref: 'products'
  }],
  createdAt: {
    type: Date,
    Default: Date.now()
  }
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;