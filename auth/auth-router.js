const router = require('express').Router();
const bcrypt = require('bcryptjs');
//import json web token library
const jwt = require('jsonwebtoken');

const secrets = require('../config/secrets.js');
const Users = require('../users/users-model.js');

// for endpoints beginning with /api/auth
router.post('/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

router.post('/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        //get JWOT
        const token = generateToken(user);
        res.status(200).json({ token });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function generateToken(user) {
  const payload = {
    username: user.username
  };
  const options = {
    expiresIn: '1d'
  };
  //payload is data, secret is signature, options object with configuration
  return jwt.sign(payload, secrets.jwtSecret, options);
};

module.exports = router;
