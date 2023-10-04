const { Router } = require("express");
const userController = require("./controller/userController");
const { isAuthenticated } = require("../../utils/middlewares/AuthMiddleware")
module.exports = (app) => {
  const router = new Router();
  app.use('/user', router);
  router.get('/:user_id', userController.get);
  router.get('/', userController.getAll);
  router.post('/', userController.create);
  router.post('/:cant', userController.bulkcreate);

  router.get('/test/winston', (req, res, next) => {
    try {
      req.logger.warn("Tuvimos una advertencia!");
      res.send("Desde user winston");
    } catch (error) {
      next(error);
    }
  });

  router.get('/test/sencilla', (req, res, next) => {
    try {
      let suma = 0;
      for (let i = 0; i < 1000000; i++) {
        suma +=i;
      }
      res.json({suma});
    } catch (error) {
      next(error);
    }
  });

  router.get('/test/compleja', (req, res, next) => {
    try {
      let suma = 0;
      for (let i = 0; i < 5e8; i++) {
        suma +=i;
      }
      res.json({suma});
    } catch (error) {
      next(error);
    }
  });
}