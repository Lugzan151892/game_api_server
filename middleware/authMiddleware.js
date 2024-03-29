const jwt = require('jsonwebtoken');
module.exports = function (res, req, next) {
    if(req.method === 'OPTIONS') {
        next()
    }
    try {
        const token = req.headers.authorization.split(' ')[1];
        if (!token) {
            return res.status(401).json({status: 401, error: true, message: "Не авторизован"})
        }
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        req.user = decoded;
        next();
    } catch(e) {
        res.status(401).json({status: 401, error: true, message: "Не авторизован"});
    } finally {
        console.log(req.headers.authorization.split(' ')[1]);
    }
}