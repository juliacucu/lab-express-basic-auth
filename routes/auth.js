const express = require("express");
const UserModel = require("../models/User.model");
const router = express.Router();
const bcryptjs = require("bcryptjs");
const saltRounds = 10;

//Sing up
router.get("/auth/sign-up", (req, res, next) => {
  res.render("auth/sign-up.hbs");
});

router.post("/auth/sign-up", (req, res, next) => {
  const { username, email, password } = req.body;

  bcryptjs
    .genSalt(saltRounds)
    .then((salt) => bcryptjs.hash(password, salt))
    .then((hashedPassword) => {
      return UserModel.create({
        username,
        email,
        passwordHash: hashedPassword,
      });
    })
    .then((userCreated) => console.log(userCreated))
    .catch((error) => next(error));
});

//Log-in
router.get("/auth/log-in", (req, res, next) => {
  res.render("auth/log-in.hbs");
});

router.post("/auth/log-in", (req, res, next) => {
  const { email, password } = req.body;
 
  if (email === "" || password === "") {
    res.render("auth/log-in", {
      errorMessage: "Please enter both, email and password to login.",
    });
    return;
  }

  UserModel.findOne({ email })
    .then((user) => {
      if (!user) {
        res.render("auth/log-in", {
          errorMessage: "Email is not registered. Try with other email.",
        });
        return;
      } else if (bcryptjs.compareSync(password, user.passwordHash)) {
        res.render("user/user-profile", { user });
      } else {
        res.render("auth/log-in", { errorMessage: "Incorrect password." });
      }
    })
    .catch((error) => next(error));
});

module.exports = router;
