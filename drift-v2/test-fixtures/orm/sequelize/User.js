// Sequelize model definition with sensitive fields
const { DataTypes } = require("sequelize");

module.exports = (sequelize) => {
  const User = sequelize.define("User", {
    id: { type: DataTypes.UUID, primaryKey: true, defaultValue: DataTypes.UUIDV4 },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },  // SENSITIVE
    password: { type: DataTypes.STRING, allowNull: false },  // SENSITIVE
    ssn: { type: DataTypes.STRING },  // SENSITIVE
    name: { type: DataTypes.STRING, allowNull: false },
    role: { type: DataTypes.ENUM("admin", "user"), defaultValue: "user" },
  });
  return User;
};
