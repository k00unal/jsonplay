var fs = require("fs");
var bodyParser = require("body-parser");
var jsonServer = require("json-server");
var jwt = require("jsonwebtoken");

// Next use the create() method to return an Express server
var server = jsonServer.create();

// Call the router() method to return an Express router
var router = jsonServer.router("./db.json");

// Now you need to read and JSON parse the users.json file which you first need to create. This file acts like a table for registered users.
var userdb = JSON.parse(fs.readFileSync("./users.json", "UTF-8"));

// Next, set default middlewares (logger, static, cors and no-cache)
// default setting
// server.use(jsonServer.defaults());

// custom setting
server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());

// Next define some constants: SECRET_KEY is used to sign the payloads and expiresIn for setting the time of expiration for JWT access tokens.
var SECRET_KEY = "123456789";
var expiresIn = "1h";

// Create a token from a payload
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

// Verify the token
function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY, (err, decode) =>
    decode !== undefined ? decode : err
  );
}

// Check if the user exists in database
function isAuthenticated({ email, password }) {
  return (
    userdb.users.findIndex(
      user => user.email === email && user.password === password
    ) !== -1
  );
}

// Now you need to create a POST /auth/login endpoint which verifies if the user exists in the database and then create and send a JWT token to the user:
server.post("/auth/login", (req, res) => {
  var { email, password } = req.body;
  if (isAuthenticated({ email, password }) === false) {
    var status = 401;
    var message = "Incorrect email or password";
    res.status(status).json({ status, message });
    return;
  }
  var access_token = createToken({ email, password });
  res.status(200).json({ access_token });
});

// Next add an Express middleware that checks that the authorization header has the Bearer scheme then verifies if the token if valid for all routes except the previous route since this is the one we use to login the users.

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(" ")[0] !== "Bearer"
  ) {
    var status = 401;
    var message = "Bad authorization header";
    res.status(status).json({ status, message });
    return;
  }
  try {
    verifyToken(req.headers.authorization.split(" ")[1]);
    next();
  } catch (err) {
    var status = 401;
    var message = "Error: access_token is not valid";
    res.status(status).json({ status, message });
  }
});

// Finally mount json-server then run server on port 3000 using:

server.use(router);

server.listen(3000, () => {
  console.log("Run Auth API Server");
});

// You can also mount json-server on a specific endpoint (/api) using:
server.use("/api", router);
