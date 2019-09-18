//import json web token library
const jwt = require('jsonwebtoken');

const secrets = require('../config/secrets.js');

module.exports = (req, res, next) => {
  const token = req.headers.authorization;

  if (token) {
    jwt.verify(token, secrets.jwtSecret, (err, decodedToken) => {
      if (err) {
        //this means token expired or is invalid
        res.status(401).json({ message: 'Invalid Credentials' });
      } else {
        //token is good!
        req.user = {username: decodedToken.username};
        next();
      }
    });
  } else {
    res.status(400).json({ message: 'No credentials provided'});
  }
};
