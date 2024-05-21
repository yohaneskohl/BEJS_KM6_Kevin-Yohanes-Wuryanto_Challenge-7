require("dotenv").config();
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { JWT_SECRET_KEY } = process.env;
const nodemailer = require("../libs/nodemailer");
const { formattedDate } = require("../libs/formattedDate");
// const { getHTML, sendMail } = require("../libs/nodemailer");

module.exports = {
  register: async (req, res, next) => {
    try {
      const { name, email, password } = req.body;

      if (!name || !email || !password) {
        return res.status(400).json({
          status: false,
          message: "name, email, and password are required!",
          data: null,
        });
      }

      const exist = await prisma.user.findUnique({ where: { email } });
      if (exist) {
        return res.status(401).json({
          status: false,
          message: "email has already been used!",
          data: null,
        });
      }

      const encryptedPassword = await bcrypt.hash(password, 10);
      const user = await prisma.user.create({
        data: { name, email, password: encryptedPassword },
      });
      delete user.password;

      // Create a welcome notification
      const notification = await prisma.notification.create({
        data: {
          title: "Welcome!",
          message: "Your account has been created successfully.",
          createdDate: formattedDate(new Date()),
          user: { connect: { id: user.id } },
        },
      });

      // Emit the notification using Socket.io
      global.io.emit(`user-${user.id}`, notification);

      return res.status(201).json({
        status: true,
        message: "User has been successfully registered",
        data: user,
      });
    } catch (error) {
      next(error);
    }
  },

  login: async (req, res, next) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          status: false,
          message: "email and password are required!",
          data: null,
        });
      }

      const user = await prisma.user.findFirst({ where: { email } });
      if (!user) {
        return res.status(400).json({
          status: false,
          message: "invalid email or password!",
          data: null,
        });
      }

      const isPasswordCorrect = await bcrypt.compare(password, user.password);
      if (!isPasswordCorrect) {
        return res.status(400).json({
          status: false,
          message: "invalid email or password!",
          data: null,
        });
      }

      delete user.password;
      const token = jwt.sign(user, JWT_SECRET_KEY);

      // Create a login notification
      const notification = await prisma.notification.create({
        data: {
          title: "Successfully Logged In",
          message: "Enjoy your access to the web.",
          createdDate: formattedDate(new Date()),
          user: { connect: { id: user.id } },
        },
      });

      // Emit the notification using Socket.io
      global.io.emit(`user-${user.id}`, notification);

      return res.status(201).json({
        status: true,
        message: "success",
        data: { ...user, token },
      });
    } catch (error) {
      next(error);
    }
  },

  index: async (req, res, next) => {
    try {
      const { search } = req.query;

      let users = await prisma.user.findMany({
        where: { name: { contains: search, mode: "insensitive" } },
      });

      users.forEach((user) => {
        delete user.password;
      });

      res.json({
        status: true,
        message: "Users retrieved successfully",
        data: users,
      });
    } catch (error) {
      next(error);
    }
  },

  whoami: async (req, res, next) => {
    try {
      return res.status(200).json({
        status: true,
        message: "Success",
        data: req.user,
      });
    } catch (error) {
      next(error);
    }
  },

  delete: async (req, res, next) => {
    try {
      const user_id = parseInt(req.params.id);
      const user = await prisma.user.findUnique({
        where: { id: user_id },
      });

      if (!user) {
        return res.status(404).json({
          status: false,
          message: "User not found",
          data: null,
        });
      }

      await prisma.user.delete({
        where: { id: user_id },
      });

      return res.json({
        status: true,
        message: "User has been deleted successfully",
        data: null,
      });
    } catch (error) {
      next(error);
    }
  },

  forgetPass: async (req, res, next) => {
    try {
      const { email } = req.body;
      const findUser = await prisma.user.findUnique({ where: { email } });

      if (!findUser) {
        return res.status(404).json({
          status: false,
          message: "user not found",
          data: null,
        });
      }
      const token = jwt.sign({ email: findUser.email }, JWT_SECRET_KEY);
      const html = await nodemailer.getHTML("reset-confirmation.ejs", {
        name: findUser.name,
        url: `${req.protocol}://${req.get(
          "host"
        )}/api/v1/reset-password?token=${token}`,
      });
      await nodemailer.sendMail(email, "Reset your password here!", html);
      return res.status(200).json({
        status: true,
        message: "Success Send Email Forget Password",
      });
    } catch (error) {
      next(error);
    }
  },

  resetPassword: async (req, res, next) => {
    try {
      const { token } = req.query;
      const { password, newPassword } = req.body;

      if (!token) {
        return res.status(400).json({
          status: false,
          message: "Token is required!",
          data: null,
        });
      }

      if (!password || !newPassword) {
        return res.status(400).json({
          status: false,
          message: "Both password and password confirmation are required!",
          data: null,
        });
      }

      if (password !== newPassword) {
        return res.status(401).json({
          status: false,
          message:
            "Please ensure that the password and password confirmation match!",
          data: null,
        });
      }

      let encryptedNewPassword = await bcrypt.hash(password, 10);

      jwt.verify(token, JWT_SECRET_KEY, async (err, decoded) => {
        if (err) {
          return res.status(403).json({
            status: false,
            message: "Invalid or expired token!",
            data: null,
          });
        }

        const updateUser = await prisma.user.update({
          where: { email: decoded.email },
          data: { password: encryptedNewPassword },
          select: { id: true, name: true, email: true },
        });

        res.status(200).json({
          status: true,
          message: "Your password has been updated successfully!",
          data: updateUser,
        });
      });
    } catch (error) {
      next(error);
    }
  },

  pageLogin: async (req, res, next) => {
    try {
      res.render("login-email.ejs");
    } catch (error) {
      next(error);
    }
  },

  pageForgetPass: async (req, res, next) => {
    try {
      res.render("forget-pass.ejs");
    } catch (error) {
      next(error);
    }
  },

  pageResetPass: async (req, res, next) => {
    try {
      let { token } = req.query;
      res.render("reset-pass.ejs", { token });
    } catch (error) {
      next(error);
    }
  },

  pageNotification: async (req, res, next) => {
    try {
      const userId = Number(req.params.id);
      const notifications = await prisma.notification.findMany({
        where: { user_id: userId },
      });
      res.render("notification-page.ejs", {
        user_id: userId,
        notifications: notifications,
      });
    } catch (error) {
      next(error);
    }
  },
};
