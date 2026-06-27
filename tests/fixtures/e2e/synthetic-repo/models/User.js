const { DataTypes } = require('sequelize')

module.exports = (sequelize) => sequelize.define('User', {
  id: { type: DataTypes.UUID, primaryKey: true },
  tenant_id: { type: DataTypes.UUID, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false },
  role: { type: DataTypes.ENUM('admin', 'member'), defaultValue: 'member' }
})
