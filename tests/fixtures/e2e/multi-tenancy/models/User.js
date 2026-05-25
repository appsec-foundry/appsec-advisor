// Multi-tenant user model — tenant_id column present
const { DataTypes } = require('sequelize')

module.exports = (sequelize) => {
  const User = sequelize.define('User', {
    id: { type: DataTypes.UUID, primaryKey: true },
    tenant_id: { type: DataTypes.UUID, allowNull: false },  // tenant isolation column
    email: { type: DataTypes.STRING, allowNull: false },
    role: { type: DataTypes.ENUM('admin', 'member'), defaultValue: 'member' }
  })
  return User
}
