const sequelize  = require('../db');
const {DataTypes} = require('sequelize');

const User = sequelize.define('user', {
    id: {type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true},
    email: { type: DataTypes.STRING, unique: true },
    password: { type: DataTypes.STRING },
    settings: { type: DataTypes.JSON },
    spectated_users: { type: DataTypes.ARRAY(DataTypes.STRING) }
});

module.exports = {
    User
}