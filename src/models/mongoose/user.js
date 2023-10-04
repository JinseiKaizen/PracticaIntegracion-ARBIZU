const { Schema, model } = require("mongoose");

const collectionName = "users";

const collectionSchema = new Schema({
  name: String,
  lastname: String,
  email: {
    unique: true,
    type: String,
    required: true,
    index: true
  },
  password: {
    type: String
  },
  phone: {
    type: String
  },
  birthday: {
    type: Date
  },
  photo: {
    type: String,
    default: null
  },
  token: String,
  address: String,
  city_id: {
    type: Schema.Types.ObjectId,
    ref: 'cities'
  },
  state_id: {
    type: Schema.Types.ObjectId,
    ref: 'states'
  },
  zipcode_id: {
    type: Schema.Types.ObjectId,
    ref: 'zipcodes'
  },
  country_id: {
    type: Schema.Types.ObjectId,
    ref: 'countries'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  rol_id: {
    type: Schema.Types.ObjectId,
    ref: 'rol'
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

const modelEntity = model(collectionName, collectionSchema);

module.exports =  modelEntity;

// module.exports = class User {

//   async get(id = null){
//     try {
//         return id ? await modelEntity.findById(id) : await modelEntity.find({});
//     } catch (error) {
//         return {response: "Hubo un error!"};
//     }
//   }

//   async create(user){
//     return await modelEntity.create(user);
//   }

//   async update(id, user){
//     return await modelEntity.findByIdAndUpdate(id, user, { new: true });
//   }
  
// };