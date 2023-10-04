
class ErrorMiddlewares {

    static logErrors(err, req, res, next){
        console.log('[LogErrors]');
        console.error(err);
        // Incorporar Sentry u algun otro
        next(err);
    }

    static boomErrorHandler(err, req, res, next){
      if(err?.isBoom){
        const { output } = err;
        return res.status(output.statusCode).json(output.payload);
      }
      next(err);
    }

    static errorHandler(err, req, res, next){
      res.status(500).json({
        message: err.message,
        stack: err.stack
      })
    }
}

module.exports = ErrorMiddlewares;