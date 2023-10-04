const userServices = require("../services/userService");

class User {
  async get(req, res, next) {
    try {
      let { user_id } = req.params;
      const response = await userServices.get(user_id);
      res.json(response);
    } catch (error) {
      next(error);
    }
  }

  async getAll(req, res, next) {
    try {
      const response = await userServices.get();
      res.json(response);
    } catch (error) {
      next(error);
    }
  }

  async getByRole(req, res, next) {
    try {
      const { rol_id } = req.params;
      const response = await userServices.getByRole({ rol_id });
      res.json(response);
    } catch (error) {
      next(error);
    }
  }


  async create(req, res, next) {
    try {
      const response = await userServices.create(req.body);
      res.json(response);
    } catch (error) {
      next(error);
    }
  }

  async bulkcreate(req, res, next) {
    try {
      const { cant } = req.params;
      const response = await userServices.bulkcreate(Number(cant));
      res.json(response);
    } catch (error) {
      next(error);
    }
  }
  
}

module.exports = new User();