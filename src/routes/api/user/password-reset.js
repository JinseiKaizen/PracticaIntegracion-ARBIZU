const express = require('express');
const jwt = require('jwt-simple');
const moment = require('moment');

const router = express.Router();

router.post('/', async (req, res) => {
  const { email } = req.body;

  // Validación de datos

  if (!email) {
    return res.status(400).send('El correo electrónico es obligatorio');
  }

  // Búsqueda del usuario

  const user = await User.findOne({ email });

  // Validación de usuario

  if (!user) {
    return res.status(404).send('El usuario no existe');
  }

  // Generación del token

  const token = jwt.encode({ id: user._id }, process.env.APP_SECRET);
  const link = `https://www.example.com/reset-password/${token}`;
  const expiresAt = moment().add(1, 'hour').toDate();

  // Envío del correo electrónico

  const transporter = nodemailer.createTransport({
    host: 'smtp.example.com',
    port: 25,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const mailOptions = {
    from: 'info@example.com',
    to: email,
    subject: 'Restablecimiento de contraseña',
    text: `
      Se ha solicitado un restablecimiento de contraseña para su cuenta.

      Haga clic en el siguiente enlace para restablecer su contraseña:

      ${link}

      Este enlace expirará en 1 hora.
    `,
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error al enviar el correo electrónico');
    }

    res.status(200).send({
      link,
      expiresAt,
    });
  });
});

module.exports = router;
Archivo routes/api/users/password-update.js:

const express = require('express');
const jwt = require('jwt-simple');
const bcrypt = require('bcryptjs');

const router = express.Router();

router.post('/', async (req, res) => {
  const { token, newPassword } = req.body;

  // Validación de token

  try {
    const decodedToken = jwt.decode(token, process.env.APP_SECRET);
  } catch (err) {
    return res.status(401).send('Token no válido');
  }

  // Validación de contraseña

  if (!newPassword) {
    return res.status(400).send('La nueva contraseña es obligatoria');
  }

  // Búsqueda del usuario

  const user = await User.findById(decodedToken.id);

  // Validación de usuario

  if (!user) {
    return res.status(404).send('El usuario no existe');
  }

  // Encriptación de contraseña

  const salt = await bcrypt.genSalt();
  const hashedPassword = await bcrypt.hash(newPassword, salt);

  // Actualización de la contraseña

  user.password = hashedPassword;
  await user.save();

  // Respuesta

  res.status(200).send();
});

module.exports = router;