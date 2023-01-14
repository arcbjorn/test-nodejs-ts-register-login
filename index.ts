const express = require("express");
const bcrypt = require("bcryptjs");
const joi = require("joi");
const app = express();
const port = 3000;

import { Request, Response } from "express";

const SALT_POWER = 10;

enum UserType {
  USER = "user",
  ADMIN = "admin",
}

interface UserDto {
  username: string;
  email: string;
  type: UserType;
  password: string;
}

interface UserEntry {
  email: string;
  type: UserType;
  // do not need to store salt, hash is enough
  // salt: string;
  passwordhash: string;
}

const UserSchema = joi
  .object({
    username: joi.string().alphanum().min(3).max(24).required(),
    password: joi
      .string()
      .regex(/^(?=.{5,})(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$/)
      .min(5)
      .max(24)
      .required(),
    email: joi.string().email().required(),
  })
  .with("username", "password");

// Database mock where the username is the primary key of a user.
const MEMORY_DB: Record<string, UserEntry> = {};

// CODE HERE
//
// I want to be able to register a new unique user (username and password). After the user is created I
// should be able to login with my username and password. If a user register request is invalid a 400 error
// should be returned, if the user is already registered a conflict error should be returned.
// On login the users crendentials should be verified.
// Because we dont have a database in this environment we store the users in memory. Fill the helper functions
// to query the memory db.

function getUserByUsername(name: string): UserEntry | undefined {
  return MEMORY_DB[name];
}

function getUserByEmail(email: string): UserEntry | undefined {
  return Object.values(MEMORY_DB).find((user) => user.email === email);
}

// Request body -> UserDto
app.get("/register", async (req: Request, res: Response) => {
  // Validate user object using joi
  // - username (required, min 3, max 24 characters)
  // - email (required, valid email address)
  // - type (required, select dropdown with either 'user' or 'admin')
  // - password (required, min 5, max 24 characters, upper and lower case, at least one special character)

  if (getUserByUsername(req.body.username)) {
    res.write("User with this username already exists");
    res.writeHead(400);
    return;
  }

  try {
    await UserSchema.validateAsync(req.body);
    const value = await joi.assert(req.body, UserSchema);

    const passwordhash = await bcrypt.hash(value.password, SALT_POWER);

    MEMORY_DB[value.username] = {
      email: value.email,
      type: value.type,
      passwordhash,
    };

    res.writeHead(200);
    res.write("OK");
  } catch (err) {
    res.writeHead(400);
  }
});

// Request body -> { username: string, password: string }
app.post("/login", async (req: Request, res: Response) => {
  // Return 200 if username and password match
  // Return 401 else

  const user = getUserByUsername(req.body.username);
  if (!user) {
    res.write("User not found");
    res.writeHead(401);
    return;
  }

  bcrypt.compare(
    req.body.password,
    user.passwordhash,
    function (_: Error, result: boolean) {
      if (result) {
        res.writeHead(200);
        res.write("OK");
      } else {
        res.write("Wrong password");
        res.writeHead(401);
      }
    }
  );
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
