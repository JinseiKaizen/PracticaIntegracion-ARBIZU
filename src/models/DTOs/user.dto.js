

const { createHash, isValidPassword } = require("../../utils/bcrypt");

module.exports = class User {
  constructor(userData){
    this.name = userData?.name;
    this.lastname = userData?.lastname;
    this.email = userData?.email;
    this.password = userData?.password;
    this.phone = userData?.phone;
    this.birthday = userData?.birthday;
    this.photo = userData?.photo;
    this.address = userData?.address;
    this.city = userData?.city;
    this.state = userData?.state;
    this.zipcode = userData?.zipcode;
    this.country = userData?.country;
    this.isActive = userData?.isActive;
    this.rol_id = userData?.rol_id;
    this.password = createHash(userData.password),
    this.token = "";
    this.createdAt= new Date().toLocaleDateString();
    this.updatedAt= null;
    this.deletedAt= null;
  }
}