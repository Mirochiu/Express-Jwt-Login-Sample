const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const app = express();
const morgan = require("morgan");
const cors = require("cors");

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

let CorsOptions = {};
let Logger;

// full access log under development
if (process.env.NODE_ENV === "development") {
  Logger = morgan("dev");
  CorsOptions = { origin: "*" };
} else {
  Logger = morgan("tiny");
  const allowedOrigins = [process.env.hosturl];
  CorsOptions.origin = function (origin, callback) {
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  };
  //https://stackoverflow.com/questions/24015292
  app.enable("trust proxy"); // for heroku
  // general cases
  app.use(function (req, res, next) {
    if (
      req.secure || // not work in heroku
      req.headers["x-forwarded-proto"] === "https"
    ) {
      return next();
    }
    res.redirect("https://" + req.headers.host);
  });
}

app.use(cors(CorsOptions));
app.use(Logger);

app.get("/api", (req, res) => {
  res.json({
    message: "welcome to the api"
  });
});

// just a example, please do not use this in your production
const UserList = [
  { name: "myuser", password: "mypwd1314", other: "i dnot known" }
];

app.post("/api/login", async (req, res) => {
  const reqData = req.body;
  let user = UserList.find(
    ({ name, password }) =>
      name === reqData.name && password === reqData.password
  );
  if (user === undefined) {
    return res.sendStatus(404);
  }
  user = Object.assign({}, user);
  delete user.password;
  const jwtPayload = { user: user };
  jwt.sign(
    jwtPayload,
    process.env.jwtsecret,
    {
      expiresIn: process.env.jwtexp,
      subject: process.env.hosturl,
      issuer: user.name
    },
    (err, token) => {
      if (err) {
        res.sendStatus(500);
      } else {
        res.json({
          message: "user login successfully",
          user,
          token
        });
      }
    }
  );
});

app.post("/api/verify", [extractToken, verifyJwt], (req, res) => {
  if (req.jwtPayload) {
    return res.json({ message: "verified user", ...req.jwtPayload });
  } else {
    return res.status(401); // unauthorized
  }
});

// should put "auth-token" into your request header
// and the login token should be preceded by JWT and a blank space.
// for example, HEADER['auth-token']=`JWT ${TOKEN_FROM_LOGIN}`
function extractToken(req, res, next) {
  const bearerHeader = req.headers["auth-token"];
  if (bearerHeader !== undefined) {
    var bearer = bearerHeader.split("JWT ");
    if (bearer.length > 1) {
      req.token = bearer[1];
    }
    next();
  } else {
    res.sendStatus(403); // forbidden
  }
}

function verifyJwt(req, res, next) {
  jwt.verify(req.token, process.env.jwtsecret, (err, auth) => {
    if (err) {
      return res.sendStatus(401); // unauthorized
    }
    if (auth.sub !== process.env.hosturl) {
      return res.sendStatus(401); // unauthorized
    }
    req.jwtPayload = { user: auth.user };
    next();
  });
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`server running on ${PORT}`);
});
