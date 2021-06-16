const express = require("express");
const bodyParser = require("body-parser");
const JsonDB = require("node-json-db").JsonDB;
const Config = require("node-json-db/dist/lib/JsonDBConfig").Config;
const { v4: uuidv4 } = require("uuid");
const speakeasy = require("speakeasy");
var QRCode = require("qrcode");
var cors = require("cors");

const app = express();

app.use(express.json());
app.use(cors());

//database configuration
const dbConfig = new Config("Database", true, false, "/");

//creating new DB
const DB = new JsonDB(dbConfig);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

//Routes
app.get("/", (req, res) => {
  res.json({
    message: "Welcome to two factor authentication",
  });
});

//registration
app.post("/api/register", (req, res) => {
  const { name } = req.body;

  const id = uuidv4();

  try {
    const path = `/user/${id}`;

    //temporary secret before verification

    const temp_secret = speakeasy.generateSecret();

    //checking for empty value

    if (!name) {
      return res.json({
        error: "Please enter name",
      });
    }

    //create a user in db
    DB.push(path, { id, name, temp_secret });

    //send user id and base32 key to user
    QRCode.toDataURL(temp_secret.otpauth_url, function (err, url) {
      console.log(url);
      if (err) {
        res.json({
          error: "something wrong can't show QR",
        });
      }
      return res.json({
        url,
      });
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Error generating secret key" });
  }
});

//verification
app.post("/api/verify", (req, res) => {
  const { userId, token } = req.body;
  try {
    //retrieve user from database
    const path = `/user/${userId}`;
    const user = DB.getData(path);
    console.log({ user });

    const { base32: secret } = user.temp_secret;

    const verified = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
    });

    if (verified) {
      DB.push(path, {
        id: userId,
        secret: user.temp_secret,
      });
      res.json({
        verified: true,
      });
    } else {
      res.json({
        verified: false,
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({
      message: "Error retrieving user",
    });
  }
});

//validation

app.post("/api/validate", (req, res) => {
  const { userId, token } = req.body;
  try {
    //retrieve user from database
    const path = `/user/${userId}`;
    const user = DB.getData(path);
    console.log({ user });

    const { base32: secret } = user.secret;

    const tokenValidates = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (tokenValidates) {
      res.json({
        validated: true,
      });
    } else {
      res.json({
        validated: false,
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({
      message: "Error retrieving user",
    });
  }
});

const Port = 5000;

app.listen(Port, () => {
  console.log(`App is running on ${Port}`);
});
