const { config } = require('../config');

let User;

switch (config.persistence) {
  case "MONGO":
    User = require('./mongoose/user');
    break;
  case "MEMORY":
    User = require('./memory/user');
    break;
  case "FILE":
    User = require('./files/user');
    break;
  case "SQL":
      User = require('./sequelize/user');
      break;
  default:
    User = require('./mongoose/user');
};

module.exports = {
  User
}