require("dotenv").config();
const express = require("express");
const router = express.Router();

const jwt = require("jsonwebtoken");
const swaggerUI = require("swagger-ui-express");
const YAML = require("yaml");
const auth = require("../controllers/auth.controllers");
const restrict = require("../middlewares/auth.middlewares");

const { PrismaClient } = require("@prisma/client");
const fs = require("fs");



// const swagger_path = path.resolve(__dirname, "../docs/api-docs.yaml");
// const file = fs.readFileSync(swagger_path, "utf-8");

// // API Docs
// const swaggerDocument = YAML.parse(file);
// router.use("/api-docs", swaggerUI.serve, swaggerUI.setup(swaggerDocument));

router.post("/register", auth.register);
router.post("/login", auth.login);
router.get("/index",  auth.index);
router.delete("/delete/:id", restrict, auth.delete);
router.get("/whoami", restrict, auth.whoami);



//forget pass
router.post("/forget-password", auth.forgetPass);
router.post("/reset-password", auth.resetPassword);


//render ejs
router.get("/login", auth.pageLogin);
router.get("/forget-password", auth.pageForgetPass);
router.get("/reset-password", auth.pageResetPass);


//notification
router.get("/users/:id/notification", auth.pageNotification);

module.exports = router;
