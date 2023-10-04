const userModel = require("../../../models/mongoose/user");
const { createHash, isValidPassword } = require("../../../utils/bcrypt");
const JWTService = require("../../../utils/JWT/jwt");
const faker = require("faker");

class User {

  async get(id = null) {
    return id ? await userModel.findById(id) : await userModel.find({});
  }

  async getByRole(query = {}) {
    return await userModel.find({ ...query });
  }

  async create(userObj) {
    let newUser = {
      ...userObj,
      password: createHash(userObj.password),
      token: ''
    };
    let user = await userModel.create(newUser);
    let token = await JWTService.generateJWT({ id: user._id });
    return await userModel.findByIdAndUpdate(user._id, { token }, { new: true });
  }

  async bulkcreate(cant = 5) {
    let usersBulk = [];
    for (let i = 0; i < cant; i++) {
      const name = faker.name.firstName();
      const lastName = faker.name.lastName();
      const email = `${name}_${faker.internet.email()}`;
      const password = faker.internet.password();
      usersBulk.push({
        name,
        last_name: lastName,
        email,
        password,
      });
    }
    return usersBulk;
  }

  async findByEmail(email) {
    return await userModel.findOne({
      email: email
    });
  }

}

module.exports = new User();