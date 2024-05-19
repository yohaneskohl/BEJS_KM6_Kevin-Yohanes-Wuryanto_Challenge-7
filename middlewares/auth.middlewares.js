const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
let { JWT_SECRET_KEY } = process.env;

module.exports = async (req, res, next) => {
    let { authorization } = req.headers;
    if (!authorization || !authorization.split(" ")[1]) {
      return res.status(400).json({
        status: false,
        message: "Token not provided",
        data: null,
      });
    }

    let token = authorization.split(" ")[1];
    jwt.verify(token, JWT_SECRET_KEY, (err, user) => {
      if (err) {
        return res.status(401).json({
          status: false,
          message: err.message,
          data: null,
        });
      }
      delete user.iat;
      req.user = user;
      next();
  });

  
};