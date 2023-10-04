
class User {
  static instancia = undefined;
  constructor() {
    if (User.instancia) {
      return User.instancia;
    }
    this.usuarios = [];
    User.instancia = this;
  }

  get(id){
    return id ? this.usuarios.filter(user => user._id == Number(id)) : this.usuarios;
  }

  create(obj) {
    const user = {
      _id: this.validateId(this.usuarios),
      ...obj
    }
    this.usuarios.push(user);
    return user;
  }

  update(id, obj){
    let indice = 0;
    this.usuarios = this.usuarios.map((user, i) => {
      if(user._id === id){
        user = {
          ...user,
          ...obj
        }
        indice = i;
      }
      return user;
    });
    return this.usuarios[indice];
  }

  validateId(arr) {
    if (arr.length) {
      let idMayor = arr.reduce((p, c) => {
        return c._id > p ? c._id : p;
      }, 0);
      return idMayor + 1;
    }
    return 1;
  }
  

}

module.exports = User;