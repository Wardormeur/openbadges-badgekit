var model = require('./app/models/account')('DATABASE').methods;
var pwd = 'root'
var salt = model.generateSalt()
console.log(salt, model.generateHash(pwd, salt));
