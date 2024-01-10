const ApiError  = require('../error/ApiError');
const { User } = require('../models/models');
const bcrypt = require('bcrypt');
const jWebToken = require('jsonwebtoken');

class UserController {
    async registration(req, res, next) {
        try {
            const {email, password} = req.body;
            if (!email || !password) {
                return next(ApiError.badRequest('Bad password or email'));
            }
            const existedUser = await User.findOne({ where: {email}});
            if (existedUser) {
                return next(ApiError.badRequest('Пользователь с такими данными уже существует'));
            }
            const hashPassword = await bcrypt.hash(password, 5);
            const user = await User.create({email, password: hashPassword, settings: JSON.stringify({}), spectated_users: []});
            const token = jWebToken.sign(
                {id: user.id, email: user.email, settings: user.settings, spectated_users: user.spectated_users},
                process.env.SECRET_KEY,
                {expiresIn: '24h'}
            );
            return res.json({status: 200, error: false, token});
        } catch {
            return res.status(500).json({message: 'Unhandled error', error: true, status: 500})
        }
    }
    async login(req, res, next) {
        try {
            const { email, password } = req.body;
            const user = await User.findOne({where: {email}});
            if (!user) {
                return next(ApiError.badRequest('Пользователь не найден'));
            }
            let comparePasword = bcrypt.compareSync(password, user.password);
            if (!comparePasword) {
                return next(ApiError.badRequest('Указан неверный пароль'));
            }
            const responseUser = {id: user.id, email: user.email, settings: JSON.parse(user.settings), spectated_users: user.spectated_users};
            const token = jWebToken.sign(
                responseUser,
                process.env.SECRET_KEY,
                {expiresIn: '24h'}
            );
            return res.json({status: 200, error: false, token, user: responseUser});
        } catch {
            return res.status(500).json({message: 'Unhandled error', error: true, status: 500})
        }
    }
    async check(req, res, next) {
        try {
            const authToken = req.headers.authorization.split(' ')[1];
            if (!authToken) {
                return res.status(401).json({status: 401, error: true, message: "Не авторизован"})
            }
            const decoded = jWebToken.verify(authToken, process.env.SECRET_KEY);
            const user = await User.findOne({where: {email: decoded.email}});
            const responseUser = {id: user.id, email: user.email, settings: JSON.parse(user.settings), spectated_users: user.spectated_users};
            const token = jWebToken.sign(
                responseUser,
                process.env.SECRET_KEY,
                {expiresIn: '24h'}
            );
            return res.json({status: 200, error: false, token, user: responseUser});
        } catch(e) {
            res.status(401).json({status: 401, error: true, message: "Не авторизован"});
        }
    }
    async saveUser(req, res, next) {
        try {
            const { email, settings } = req.body;
            const existedUser = await User.findOne({ where: {email}});
            existedUser.settings = JSON.stringify(settings);
            await existedUser.save();
            const user = await User.findOne({ where: {email}});

            const responseUser = { id: user.id, email: user.email, settings: JSON.parse(user.settings), spectated_users: user.spectated_users };
            const token = jWebToken.sign(
                responseUser,
                process.env.SECRET_KEY,
                {expiresIn: '24h'}
            );
            return res.json({status: 200, error: false, token, user: responseUser });
        } catch {
            res.status(401).json({status: 401, error: true, message: "При сохранении произошла ошибка"});
        }
    }
    async getUser(req, res, next) {
        try {
            const authToken = req.headers.authorization.split(' ')[1];
            if (!authToken) {
                return res.status(401).json({status: 401, error: true, message: "Не авторизован"})
            }
            const decoded = jWebToken.verify(authToken, process.env.SECRET_KEY);
            const user = await User.findOne({where: {email: decoded.email}});
            const responseUser = {id: user.id, email: user.email, settings: JSON.parse(user.settings), spectated_users: user.spectated_users};
            return res.json({status: 200, error: false, user: responseUser});
        } catch {
            res.status(401).json({status: 401, error: true, message: "При запросе произошла ошибка"});
        }
    }
}

module.exports = new UserController();