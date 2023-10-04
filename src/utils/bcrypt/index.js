const bcrypt = require("bcrypt");

const isValidPassword = (password, user) => bcrypt.compareSync(password, user.password);

const createHash = password => bcrypt.hashSync(password, bcrypt.genSaltSync(10));

module.exports = {
    isValidPassword,
    createHash
}