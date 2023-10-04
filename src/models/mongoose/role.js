const { Schema, model } = require("mongoose");

const collectionName = "roles";

const collectionSchema = new Schema({
    name: {
        type: String,
        enum: ['ADMIN', 'OPERATIONS', 'USER'],
        default: 'ADMIN',
        unique: true
      },
      description: String
});

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;