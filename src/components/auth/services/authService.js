
const userService = require("../../user/services/userService");
const JWTService = require("../../../utils/JWT/jwt");
const { createHash, isValidPassword } = require("../../../utils/bcrypt");
const faker = require("faker");
const Boom = require("@hapi/boom");
class Auth {

  async login({email, password, transfer = false}, {cart, wishlist}){
    const user = await userService.findByEmail(email);
    if(!user) throw Boom.unauthorized("Credenciales inválidas");
    if(!isValidPassword(password, user)) throw Boom.unauthorized("Credenciales inválidas");
    const token = await JWTService.generateJWT({id: user._id});
    return await userService.updateUser(user._id, {token});
  }

  async bulkCreate(cant){
    try {
      for (let i = 0; i < cant; i++) {
        const product = {
          "nombre": faker.commerce.productName(),
          "descripcion": faker.lorem.sentence(),
          "precio": faker.commerce.price(),
          "stock": faker.random.number(),
          "imagen": faker.image.imageUrl()
        }
        await userService.create(product);
      }
      return {res: true};
    } catch (error) {
      console.log(error);
    }
  }
}

module.exports = new Auth();