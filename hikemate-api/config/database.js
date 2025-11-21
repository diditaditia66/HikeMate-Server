const { Sequelize } = require('sequelize');

const sequelize = new Sequelize('hikemate', 'hikemate', 'Aditya0410', {
  host: 'hikemate-db.cvsueigkskd6.ap-northeast-3.rds.amazonaws.com',
  port: 5432,
  dialect: 'postgres',
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false,
    },
  },
  logging: false,
});

module.exports = sequelize;
