const mongoose = require("mongoose");
const { mongo } = require("./");
mongoose.set("debug", true);
mongoose.set("strictQuery", false);


class MongoDB{
  static instance;
  constructor(){
    if(MongoDB.instance){
      return MongoDB.instance;
    }
    this.connection = this.connect();
    MongoDB.instance = this;
  }

  async connect(){
    try {
      let connection = await mongoose.connect(mongo.mongo_atlas);
      console.log(" ~~ Conexión exitosa a la base de Datos ~~ ");
      return connection
    } catch (error) {
      console.log(error);
      console.log("No se pudo conectar!");
    }
  }
}

module.exports = MongoDB;


