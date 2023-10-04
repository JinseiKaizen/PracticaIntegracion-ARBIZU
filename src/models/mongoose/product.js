const { Schema, model } = require("mongoose");

const collectionName = "products";

const sizeSchema = new Schema({
  stock: Number,
  sold: Number,
  isActive: Boolean,
  countStock: Boolean
}, { _id: false }); // No se generará un _id para los subdocumentos de tamaño

const imageItemSchema = new Schema({
  color_id: {
    type: Schema.Types.ObjectId,
    ref: 'colors'
  },
  urls: [String]
}, { _id: false });

const collectionSchema = new Schema({
  title: String,
  description: String,
  colors: [{
    type: Schema.Types.ObjectId,
    ref: 'colors'
  }],
  images: [imageItemSchema],
  sizes: {
    type: Map,
    of: sizeSchema
  },
  composition: String,
  category_id: {
    type: Schema.Types.ObjectId,
    ref: 'categories'
  },
  made_in: {
    type: Schema.Types.ObjectId,
    ref: 'countries'
  },
  care_instructions: [{
    type: Schema.Types.ObjectId,
    ref: 'care_instructions'
  }],
  product_type_id: [{
    type: Schema.Types.ObjectId,
    ref: 'product_type'
  }],
  outfits: [{
    type: Schema.Types.ObjectId,
    ref: 'outfit'
  }],
  price: {
    type: Map,
    of: Schema.Types.Decimal128
  },
  model_info: String,
  eco_friendly: {
    type: Boolean,
    default: false
  },
  is_premium: {
    type: Boolean,
    default: false
  },
  is_new: {
    type: Boolean,
    default: true
  },
  is_active: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    Default: Date.now()
  },
  updatedAt: {
    type: Date,
    Default: null
  },
  deletedAt: {
    type: Date,
    Default: null
  }
});

function applyPopulate(doc) {
  return doc.populate("colors")
            .populate("category_id")
            .populate("product_type_id")
            .populate({
              path: "images.color_id",
              model: "colors" 
            })
}

collectionSchema.pre('find', function(){ applyPopulate(this); })

// Método estático personalizado
collectionSchema.statics.findByIdWithPopulate = async function(id) {
  return applyPopulate(this.findById(id))
              .populate("care_instructions")
              .populate("made_in")
};

const modelEntity = model(collectionName, collectionSchema);

module.exports = modelEntity;