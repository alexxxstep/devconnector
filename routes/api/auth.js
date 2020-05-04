const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');

const { check, validationResult } = require('express-validator');

const auth = require('../../middleware/auth');

const User = require('../../models/User');

// @route GET api/auth
// @desc Test route
// @access Public
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route POST api/auth
// @desc Authenticate user and get token
// @access Public
router.post(
  '/',
  [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Passwors is required').exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      // See if user exists
      let user = await User.findOne({ email });
      // Get users
      if (!user) {
        return res.status(400).json({
          errors: [{ msg: 'User is not exist' }],
        });
      }

      const inMatch = await bcrypt.compare(password, user.password);

      if (!inMatch) {
        return res.status(400).json({
          errors: [{ msg: 'Password is not valid' }],
        });
      }

      // Return jsonwebtoken
      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: 300000 },
        (err, token) => {
          // console.log('err:', err);
          console.log('token:', token);
          if (err) throw err;
          res.json({ token });
          // console.log('token:', token);
        }
      );

      // res.send('User registered');
    } catch (err) {
      console.log(err.message);
      res.status(500).send(err.message);
    }
  }
);

module.exports = router;
