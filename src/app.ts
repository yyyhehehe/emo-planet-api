import express from "express";

import cors from "cors";

import argon2 from "argon2";

import Sequelize from "sequelize";

const app = express();
app.use(express.json());
app.use(cors());

const sequelize = new Sequelize(process.env.DATABASE!, { logging: true });

app.get("/", (req, res) => {
  res.send();
});

interface Tester {
  username: string;
  password: string;
}

const usernamePattern = /^[a-zA-Z\d]{6,16}$/;
const passwordPattern = /^[a-zA-Z\d]{8,16}$/;

app.post("/auth", async (req, res) => {
  try {
    const { username, password } = req.body as Tester;
    if (!(usernamePattern.test(username) && passwordPattern.test(password))) {
      res.sendStatus(500);
    }
    const tester: any = (await sequelize.query({
      query: `SELECT * FROM Tester WHERE username = ?`,
      values: [username],
    }, { type: sequelize.QueryTypes.SELECT }))[0];

    if (tester) {
      if (await argon2.verify(tester.passwordHash, password)) {
        res.sendStatus(200);
      } else {
        res.sendStatus(401);
      }
    } else {
      await sequelize.query({
        query: `INSERT Tester SET username = ?, passwordHash = ?`,
        values: [username, await argon2.hash(password)],
      });
      res.sendStatus(200);
    }
  } catch (ex) {
    res.sendStatus(500);
  }
});

app.listen(process.env.PORT, () => console.log(`listening ${process.env.PORT}`));
