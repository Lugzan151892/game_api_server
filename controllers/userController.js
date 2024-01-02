const ApiError  = require('../error/ApiError');
const {User} = require('../models/models');
const bcrypt = require('bcrypt');
const jWebToken = require('jsonwebtoken');

class UserController {
    async registration(req, res, next) {
        const {email, password} = req.body;
        if (!email || !password) {
            return next(ApiError.badRequest('Bad password or email'));
        }
        const existedUser = await User.findOne({ where: {email}});
        if (existedUser) {
            return next(ApiError.badRequest('Пользователь с такми email уже существует'));
        }
        const hashPassword = await bcrypt.hash(password, 5);
        const user = await User.create({email, password: hashPassword, settings: {}, spectated_users: []});
        const token = jWebToken.sign(
            {id: user.id, email: user.email}, 
            process.env.SECRET_KEY,
            {expiresIn: '24h'}
        );
        return res.json({token});
    }
    async login(req, res, next) {
        const { email, password } = req.body;
        const user = await User.findOne({where: {email}});
        if (!user) {
            return next(ApiError.badRequest('Пользователь не найден'));
        }
        let comparePasword = bcrypt.compareSync(password, user.password);
        if (!comparePasword) {
            return next(ApiError.badRequest('Указан неверный пароль'));
        }
        const token = jWebToken.sign(
            {id: user.id, email: user.email},
            process.env.SECRET_KEY,
            {expiresIn: '24h'}
        );
        return res.json({token});
    }
    async check(req, res, next) {
        const token = jWebToken.sign(
            {id: req.user.id, email: req.user.email},
            process.env.SECRET_KEY,
            {expiresIn: '24h'}
        );
        return res.json({token});
    }
}

module.exports = new UserController();