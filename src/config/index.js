require('dotenv').config();
const config = {
    port: process.env.PORT,
    cookie_key: process.env.COOKIE_KEY,
    session_key: process.env.SESSION_KEY,
    jwt_secret: process.env.JWT_SECRET,
    jwt_algorithm: process.env.HS256,
    jwt_experies: process.env.JWT_EXPERIES_IN,
    persistence: process.env.PERSISTENCIA,
    node_mailer_user: process.env.NODE_MAILER_USER,
    node_mailer_password: process.env.NODE_MAILER_PASSWORD,
    twilio_sid: process.env.TWILIO_ACC_SID,
    twilio_auth_token: process.env.TWILIO_AUTH_TOKEN,
    twilio_phone_number: process.env.TWILIO_PHONE,
    isProd: process.env.NODE_ENV === "production"
}

const mongo = {
    mongo_local: process.env.MONGO_LOCAL,
    mongo_atlas: process.env.MONGO_ATLAS
  }
  
  module.exports = { config, mongo };