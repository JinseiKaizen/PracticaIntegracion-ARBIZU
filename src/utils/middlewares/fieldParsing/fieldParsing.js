

const parseJsonFields = (req, res, next) => {
  // Iterar sobre cada campo en el cuerpo de la solicitud
  for (const field in req.body) {
    if (typeof req.body[field] === "string") {
      try {
        // Intentar parsear el valor del campo como JSON
        req.body[field] = JSON.parse(req.body[field]);
      } catch (error) {
        // Si no es un JSON válido, continuar sin hacer nada
      }
    }
  }
  next();
};

module.exports = {
  parseJsonFields
}