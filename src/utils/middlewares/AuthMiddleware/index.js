const JWTService = require("../../JWT/jwt");
const userService = require("../../../components/user/services/userService");
const Boom = require("@hapi/boom"); 

class AuthMiddleware {

  static verifyRole = (...roles) => {
    return (req, res,next) => {
      try{
        if(req.user && roles.includes(req.user?.rol)) return next();
        throw Boom.forbidden('No tienes permisos');
      }catch(e){
        next(e);
      }
    }
  }

  static getAuthenticatedUser = (isAuthenticated = false) => {
    return async (req, res, next) => {
      try{
        const authorization = req.headers.authorization || '';
        if(authorization === "") {
          if (isAuthenticated) return next();
          throw Boom.badRequest('No estás enviando headers');
        }
        const token = authorization.split(' ')[1];
        if((await JWTService.verify(token))){
          let payload = await JWTService.decode(token);
          let user = await userService.get(payload.id);
          if(!user) throw Boom.conflict('Token válido pero usuario no encontrado');
          req.user = user;
          next();
        }else{
          throw Boom.unauthorized('Token no válido');
        }
      }catch(e){
        next(e);
      }
    }
  }

  static isAuthenticated = async (req, res, next) => {
    try {
      const authorization = req.headers.authorization || '';
      if(authorization === "") next();
      const token = authorization.split(' ')[1];
      if((await JWTService.verify(token))){
        let payload = await JWTService.decode(token);
        let user = await userService.get(payload.id);
        if(!user) throw Boom.conflict('Token válido pero usuario no encontrado');
        req.user = user;
        next();
      }else{
        throw Boom.unauthorized('Token no válido');
      }
    } catch (error) {
      next(error);
    }
  }

}

module.exports = AuthMiddleware;