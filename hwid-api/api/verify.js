const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const serverless = require("serverless-http");

const app = express();
app.use(express.json()); // 🔥 Needed for POST requests

// Configuration
const SECRET_KEY = process.env.SECRET_KEY || "81e2a788eb06df6d08a423d3f5f32732b3264631fcfaf906f7";
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || "4FQCglZaFCTUXZzC1hdgDmavdOdW49Qm";
const RATE_LIMIT = 5;
const RATE_LIMIT_WINDOW = 60 * 1000;

const requestCounts = new Map();
let WHITELIST = {};

// Load whitelist.json
function loadWhitelist() {
  try {
    const data = fs.readFileSync("whitelist.json", "utf8");
    WHITELIST = JSON.parse(data);
    console.log("Whitelist loaded with", Object.keys(WHITELIST).length, "entries");
  } catch (err) {
    console.error("Error loading whitelist:", err);
  }
}
loadWhitelist();

// XOR decrypt
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

// Rate limit middleware
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

// Uptime check
app.get("/", (req, res) => {
  res.status(200).send("Whitelist server running.");
});

// Main verification route
app.post("/verify", rateLimit, (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${SECRET_KEY}`) {
    return res.status(401).json({ status: "ERROR", message: "Invalid authorization" });
  }

  const { hwid, token, timestamp } = req.body;
  if (!hwid || !token || !timestamp) {
    return res.status(400).json({ status: "ERROR", message: "Missing required fields" });
  }

  let decrypted;
  try {
    decrypted = xorDecrypt(hwid, ENCRYPTION_KEY);
    console.log("Decrypted HWID:", decrypted);
  } catch (e) {
    console.error("Decryption error:", e);
    return res.status(400).json({ status: "ERROR", message: "Decryption failed" });
  }

  const serverTime = Date.now() / 1000;
  if (Math.abs(serverTime - timestamp) > 600) {
    return res.status(400).json({ status: "ERROR", message: "Expired timestamp" });
  }

  loadWhitelist(); // Reload for live updates
  const valid = WHITELIST[decrypted];
  console.log("Whitelist check:", valid);

  if (valid) {
    return res.status(200).json({ status: "VALID" });
  } else {
    return res.status(403).json({ status: "ERROR", message: "Invalid HWID" });
  }
});

module.exports = serverless(app); // ✅ Correct way to export for Vercel
