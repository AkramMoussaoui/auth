const express = require("express");
const mongoose = require("mongoose");
const User = require("./models/User");
const Token = require("./models/Token");
const morgan = require("morgan");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 2510;
const saltRounds = 10;

app.use(express.json());
app.use(morgan("tiny"));
app.use(helmet());
app.use(cors());

mongoose.connect(process.env.MONGODB_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
});

const db = mongoose.connection;

db.once("open", () => console.log("Database connected !!"));

const authenticate = (req, res, next) => {
  const token =
    req.headers.authorization && req.headers.authorization.split(" ")[1];
  if (!token) {
    res.status(401);
    next(new Error("no token provided"));
  } else {
    jwt.verify(token, process.env.JWT_SECRET, (err, email) => {
      if (err) {
        res.status(403);
        next(new Error("wrong token"));
      }
      req.email = email;
      next();
    });
  }
};

const generateToken = (email) => {
  return jwt.sign(
    {
      email,
    },
    process.env.JWT_SECRET,
    { expiresIn: "1m" }
  );
};

app.post("/logout", async (req, res, next) => {
  const token =
    req.headers.authorization && req.headers.authorization.split(" ")[1];
  if (!token) {
    res.status(401);
    next(new Error("no token provided"));
  }
  try {
    await Token.findOneAndDelete({ token });
    res.status(200);
    res.send({
      message: "successful logout",
    });
  } catch (error) {
    next(error);
  }
});

app.post("/login", async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email: email });
    if (!user) {
      res.status(404);
      throw new Error("User doesn't exist");
    }
    if (!(await bcrypt.compare(password, user.password))) {
      res.status(401);
      throw new Error("Wrong Password");
    }
    const accessToken = generateToken(email);
    const refreshToken = jwt.sign(
      {
        email,
      },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    const token = new Token({
      token: refreshToken,
    });

    await token.save();

    res.status(200);
    res.send({
      accessToken,
      refreshToken,
    });
  } catch (error) {
    next(error);
  }
});

app.post("/signup", async (req, res, next) => {
  const { email, password, amount } = req.body;
  try {
    const hash = await bcrypt.hash(password, saltRounds);
    const newUser = new User({
      email,
      password: hash,
      amount,
    });
    await newUser.save();
    res.status(200);
    res.send({
      message: "registration done successfully",
    });
  } catch (error) {
    res.status(500);
    next(error);
  }
});

app.get("/user", authenticate, async (req, res, next) => {
  const { email } = req.email;
  try {
    const user = await User.findOne({ email });
    res.status(200);
    res.send(user);
  } catch (error) {
    next(error);
  }
});

app.get("/token", async (req, res, next) => {
  const token =
    req.headers.authorization && req.headers.authorization.split(" ")[1];
  if (!token) {
    res.status(401);
    next(new Error("no token provided"));
  } else {
    jwt.verify(token, process.env.JWT_REFRESH_SECRET, (err, data) => {
      if (err) {
        res.status(403);
        next(new Error("wrong token"));
      }
      const { email } = data;
      const accessToken = generateToken(email);
      res.send({
        accessToken,
      });
    });
  }
});

app.use((err, req, res, next) => {
  if (!res.status) res.status(500);
  res.send({
    message: err.message,
  });
});

app.listen(PORT, () => console.log(`listening on http://localhost:${PORT}`));
