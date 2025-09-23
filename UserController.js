const User = require("../modeles/userModel");
const isUsername = require('../tools/isUsername');

const createUser = async (req, res, next) => {
  // console.log('Received form data:', req.body);
  const newUser = {
    username: req.body.username,
    mdp: req.body.mdp,
  };
  try {

    if (
      !isUsername(newUser.username)
    ) {
      throw new Error(
        "Le nom d'utilisateur doit contenir 3 à 20 caractères et ne doit pas contenir d'espace"
      );
    }

    const checkUsernameUnicity = await User.findByUsername(newUser.username);
    if (checkUsernameUnicity) {
      throw new Error("Username already taken");
    }

    await User.create(newUser);
    res.status(200).json({ message: "User created successfully" });
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
    // throw new Error(error);
  }
};

const getUsers = async (req, res) => {
  try {
    const users = await User.findAll();
    if (users) {
      // Créer un nouveau tableau d'utilisateurs sans le champ 'mdp'
      const usersWithoutPassword = users.map((user) => {
        const { mdp, ...userWithoutPassword } = user;
        return userWithoutPassword;
      });

      return res.status(200).json(usersWithoutPassword);
    } else {
      res.status(404).json({ message: "No users found." });
    }
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
};

const getUserById = async (req, res) => {
  try {
    // console.log(id_user);
    // console.log(req.params);
    const id_user = req.params.id_user;

    if (!isNaN(id_user)) {
      const user = await User.findById(id_user);

      if (user) {
        const { mdp, ...userWithoutPassword } = user;
        return res.status(200).json(userWithoutPassword);
      } else {
        return res.status(404).json({ message: `User #${id_user} not found` });
      }
    } else {
      return res.sendStatus(400);
    }
  } catch (error) {
    console.error(error);
    return res.sendStatus(500);
  }
};

const getUserConnected = async (req, res) => {
  try {
    // console.log(id_user);
    // console.log(req.params);
    const id_user = req.user.id_user;

    if (!isNaN(id_user)) {
      const user = await User.findById(id_user);

      if (user) {
        const { mdp, ...userWithoutPassword } = user;
        return res.status(200).json(userWithoutPassword);
      } else {
        return res.status(404).json({ message: `User #${id_user} not found` });
      }
    } else {
      return res.sendStatus(400);
    }
  } catch (error) {
    console.error(error);
    return res.sendStatus(500);
  }
};


module.exports = {
  createUser,
  getUsers,
  getUserById,
  getUserConnected,
};

// Gérer les actions liées aux réputations des utilisateurs (likes et dislikes)
// Ajouter Skill et social network
