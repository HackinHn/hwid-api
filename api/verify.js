const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const serverless = require("serverless-http");

const app = express();
app.use(express.json());

const SECRET_KEY = process.env.SECRET_KEY || "your_secret_key_here";
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || "your_encryption_key_here";
const RATE_LIMIT = 5;
const RATE_LIMIT_WINDOW = 60 * 1000;

const requestCounts = new Map();
let WHITELIST = {};

function loadWhitelist() {
  try {
    const data = fs.readFileSync(__dirname + "/whitelist.json", "utf8");
    WHITELIST = JSON.parse(data);
  } catch (err) {
    console.error("Error loading whitelist:", err);
  }
}
loadWhitelist();

function xorDecrypt(str, key) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const strBytes = encoder.encode(str);
  const keyBytes = encoder.encode(key);
  const result = new Uint8Array(strBytes.length);
  for (let i = 0; i < strBytes.length; i++) {
    result[i] = strBytes[i] ^ keyBytes[i % keyBytes.length];
  }
  return decoder.decode(result);
}

function rateLimit(req, res, next) {
  const ip = req.headers["x-forwarded-for"] || req.ip || "unknown";
  const now = Date.now();
  const data = requestCounts.get(ip) || { count: 0, timestamp: now };

  if (now - data.timestamp > RATE_LIMIT_WINDOW) {
    data.count = 0;
    data.timestamp = now;
  }

  if (data.count >= RATE_LIMIT) {
    return res.status(429).json({ status: "ERROR", message: "Rate limit exceeded" });
  }

  data.count++;
  requestCounts.set(ip, data);
  next();
}

app.get("/", (req, res) => {
  res.send("Server is working!");
});


app.post("/verify", rateLimit, (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${SECRET_KEY}`) {
    return res.status(401).json({ status: "ERROR", message: "Invalid authorization" });
  }

  const { hwid, token, timestamp } = req.body;
  if (!hwid || !token || !timestamp) {
    return res.status(400).json({ status: "ERROR", message: "Missing fields" });
  }

  let decrypted;
  try {
    decrypted = xorDecrypt(hwid, ENCRYPTION_KEY);
  } catch (e) {
    return res.status(400).json({ status: "ERROR", message: "Decryption failed" });
  }

  const serverTime = Date.now() / 1000;
  if (Math.abs(serverTime - timestamp) > 600) {
    return res.status(400).json({ status: "ERROR", message: "Expired timestamp" });
  }

  loadWhitelist();
  const valid = WHITELIST[decrypted];

  if (valid) {
    return res.status(200).json({ status: "VALID" });
  } else {
    return res.status(403).json({ status: "ERROR", message: "Invalid HWID" });
  }
});

module.exports = serverless(app);
