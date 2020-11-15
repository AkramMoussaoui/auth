const mongoose = require("mongoose");
const uniqueValidator = require("mongoose-unique-validator");
const Schema = mongoose.Schema;

const tokenSchema = Schema({
  token: {
    type: "string",
    required: true,
    unique: true,
  },
});

tokenSchema.plugin(uniqueValidator, { message: "token already exist." });
const Token = mongoose.model("token", tokenSchema);

module.exports = Token;
