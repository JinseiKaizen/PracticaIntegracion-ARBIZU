
const authService = require("../services/authService");
class Auth {

  async login(req, res, next){
    try {
      const response = await authService.login(req.body, req.session);
      res.json(response);
    } catch (error) {
      next(error);
    }
  }
  
}

module.exports = new Auth();