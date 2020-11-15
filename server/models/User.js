const mongoose = require("mongoose");
const uniqueValidator = require("mongoose-unique-validator");
const Schema = mongoose.Schema;

const userSchema = Schema({
  email: {
    type: "string",
    match: /^([\w-\.]+@([\w-]+\.)+[\w-]{2,4})?$/,
    required: [true, "email is required"],
    unique: true,
  },
  password: {
    type: "string",
    required: [true, "password is required"],
  },
  amount: {
    type: "number",
  },
});

userSchema.plugin(uniqueValidator, { message: "user already exist." });
const User = mongoose.model("user", userSchema);

module.exports = User;
