const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../modeles/userModel');
require('dotenv').config();

const login = async (req, res, next) => {
  const user = {
    email: req.body.email,
    mdp: req.body.mdp,
  };
  try {
    const userFromDB = await User.findByEmail(user.email);
    if (!userFromDB) {
      throw new Error("L'email et/ou le mot de passe est invalide");
    } else {
      const passwordCheck = await bcrypt.compare(user.mdp, userFromDB.mdp);
      if (!passwordCheck) {
        throw new Error("L'email et/ou le mot de passe est invalide");
      } else {
        user.role = userFromDB.role
        const id_user = user.id_user = userFromDB.id_user
        const token = createJwtToken(user)
        console.log('login succesful');
        return res.status(200).send({ token, id_user });
      }
    }
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Error during login', error: error.message });
  }
};

const logout = (req, res) => {
  axios.defaults.headers.common['Authorization'] = '';
  localStorage.removeItem('token');
  // return res.clearCookie('token').status(200).json({ message: 'Logout' });
};

const getTokenData = (req, res) => {
  return res.json({
    id_user: req.user.id_user,
    username: req.user.username,
  });
};

const createJwtToken = (user) => {
  return jwt.sign(
    {
      id_user: user.id_user,
      username: user.username,
    },
    process.env.JWT_SECRET_KEY,
    {
      expiresIn: parseInt(process.env.JWT_EXPIRATION)
    }
  );
}

module.exports = {
  login,
  logout,
  getTokenData
};
