const authApi = require('../components/auth');
const userApi = require('../components/user');
// const roleApi = require('../components/roles');

module.exports = app => {
    authApi(app);
    userApi(app);
    // roleApi(app);
    app.get("/", (req,res,next)=>{
        req.logger.debug("Imprimiendo desde el logger")
        console.log(req.socketIO)
        res.send("Todo ok!");
    });
    app.all("*", (req,res,next)=>{
        // req.logger.error("404 not found!")
        res.send("Este request no existe!");
    });
}