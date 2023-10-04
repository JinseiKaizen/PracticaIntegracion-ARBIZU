const express = require('express');
const sessions = require("express-session");
const MongoStore = require("connect-mongo");
const expressSessionId = require("express-session-id");
const cookie = require('cookie-parser');
const cors = require("cors")
const serverRoutes = require('./routes');
const path = require('path');
const { Server: HttpServer} = require('http');
const { config, mongo } = require("./config");
const Socket = require('./utils/socket/socket.io');
const MongoDB = require('./config/mongoDB');
const ErrorMiddlewares = require('./utils/middlewares/errorMidlewares');
const logger = require("./utils/winston");
const bcrypt = require('bcryptjs');
const jwt = require('jwt-simple');

class Server {
  constructor(){
    this.app = express();
    this.middlewares();
    this.settings();
    this.views();
    // this.sockets();
    this.routes();
    this.errorMiddlewares();
    this.mongoDB = new MongoDB();
  }

  // Modelos

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
});

const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true },
  owner: { type: String, required: true },
});

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);

// Rutas

router.post('/api/users', async (req, res) => {
  const { email, password } = req.body;

  // Validación de datos

  if (!email || !password) {
    return res.status(400).send('Los datos son obligatorios');
  }

  // Encriptación de contraseña

  const salt = await bcrypt.genSalt();
  const hashedPassword = await bcrypt.hash(password, salt);

  // Creación del usuario

  const user = new User({ email, password: hashedPassword });
  await user.save();

  // Generación del token

  const token = jwt.encode({ id: user._id }, process.env.APP_SECRET);

  // Respuesta

  res.status(201).send({ token });
});

router.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;

  // Validación de datos

  if (!email || !password) {
    return res.status(400).send('Los datos son obligatorios');
  }

  // Búsqueda del usuario

  const user = await User.findOne({ email });

  // Validación de contraseña

  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(400)
  }
  
  middlewares(){
    this.app.use(logger);
    this.app.use(cors());
    this.app.use(cookie(`${config.cookie_key}`));
    this.app.use(sessions({
      store: MongoStore.create({
        mongoUrl: mongo.mongo_atlas,
        mongoOptions: { useUnifiedTopology: true },
        ttl: 14 * 24 * 60 * 60, // = 14 days. Default
        touchAfter: 24 * 3600 // time period in seconds
      }),
      secret: config.session_key,
      resave: false,
      saveUninitialized: false,
      cookie: { secure: true },
      genid: expressSessionId()
    }));
    this.app.use((req, res, next) => {
      if (!req.session?.cart) {
        req.session.cart = [{
          _id: req.sessionID,
          createdAt: new Date().toLocaleDateString(),
          status_id: null,
          products: []
        }];
        req.session.wishlist = [];
      }
      next();
    });
  }

  settings(){
    this.app.use(express.json());
    this.app.use(express.urlencoded({extended: true}));
    this.app.use(express.static(`${__dirname}/public`));
  }

  views(){
    this.app.set('view engine', "ejs");
    this.app.set('views', path.join(__dirname, 'views', 'pages'));
  }

  sockets(){
    this.httpServer = new HttpServer(this.app);
    this.socket = new Socket(this.httpServer);
  }

  routes(){
    this.app.use((req, res, next)=>{
      req.socketIO = this.socket;
      next();
    });
    serverRoutes(this.app);
  }

  errorMiddlewares(){
    this.app.use(ErrorMiddlewares.logErrors);
    this.app.use(ErrorMiddlewares.boomErrorHandler);
    this.app.use(ErrorMiddlewares.errorHandler);
  }

  listen(){
    this.app.listen(config.port, (e) => console.log(`http://localhost:${config.port}`))
  }

}

module.exports = new Server();