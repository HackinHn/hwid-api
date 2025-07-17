const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const app = express();

app.use(express.json());

// Configuration
const SECRET_KEY = process.env.SECRET_KEY || "81e2a788eb06df6d08a423d3f5f32732b3264631fcfaf906f7"; // Store in .env
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || "4FQCglZaFCTUXZzC1hdgDmavdOdW49Qm"; // Store in .env
const RATE_LIMIT = 5; // Max requests per minute per IP
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute in milliseconds
const requestCounts = new Map(); // In-memory rate-limiting

let WHITELIST = {};

// Load whitelist.json at startup
function loadWhitelist() {
  try {
    const data = fs.readFileSync("whitelist.json", "utf8");
    WHITELIST = JSON.parse(data);
    console.log("Whitelist loaded:", Object.keys(WHITELIST).length, "entries");
  } catch (err) {
    console.error("Failed to load whitelist.json:", err);
  }
}

loadWhitelist();

// Improved XOR decryption to match Lua's byte-level XOR
function xorDecrypt(str, key) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const strBytes = encoder.encode(str); // Convert to UTF-8 bytes
  const keyBytes = encoder.encode(key); // Convert key to UTF-8 bytes
  let result = new Uint8Array(strBytes.length);

  for (let i = 0; i < strBytes.length; i++) {
    result[i] = strBytes[i] ^ keyBytes[i % keyBytes.length];
  }
  return decoder.decode(result); // Convert back to string
}

// Rate-limiting middleware
function rateLimit(req, res, next) {
  const clientIp = req.headers["x-forwarded-for"] || req.ip || "unknown";
  const currentTime = Date.now();
  const clientData = requestCounts.get(clientIp) || { count: 0, timestamp: currentTime };

  if (currentTime - clientData.timestamp > RATE_LIMIT_WINDOW) {
    clientData.count = 0;
    clientData.timestamp = currentTime;
  }

  if (clientData.count >= RATE_LIMIT) {
    return res.status(429).json({ status: "ERROR", message: "Rate limit exceeded" });
  }

  clientData.count += 1;
  requestCounts.set(clientIp, clientData);
  next();
}

// Basic GET route for uptime checking
app.get("/", (req, res) => {
  res.status(200).send("Whitelist server is running.");
});

// POST /verify route for Lua script
app.post("/verify", rateLimit, (req, res) => {
  // Verify Authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${SECRET_KEY}`) {
    return res.status(401).json({ status: "ERROR", message: "Invalid authorization" });
  }

  // Log raw request body
  console.log("Raw Request Body:", req.body);

  // Parse request body
  const { hwid, token, timestamp } = req.body; // Use plain timestamp from client
  if (!hwid || !token || !timestamp) {
    return res.status(400).json({ status: "ERROR", message: "Missing HWID, token, or timestamp" });
  }

  // Decrypt HWID
  let decryptedHwid;
  try {
    decryptedHwid = xorDecrypt(hwid, ENCRYPTION_KEY);
    console.log("Decrypted HWID:", decryptedHwid); // Debug log
  } catch (err) {
    console.error("HWID Decryption Error:", err);
    return res.status(400).json({ status: "ERROR", message: "Invalid HWID format" });
  }

  // Validate timestamp with debug and increased window
  const serverTime = Date.now() / 1000;
  console.log("Received Timestamp:", timestamp); // Debug log
  console.log("Server Time:", serverTime); // Debug log
  console.log("Time Difference:", Math.abs(serverTime - timestamp)); // Debug log
  if (!timestamp || Math.abs(serverTime - timestamp) > 600) { // Increased to 10 minutes
    return res.status(400).json({ status: "ERROR", message: "Invalid or expired token" });
  }

  // Reload whitelist to get live changes
  loadWhitelist();

  // Verify HWID
  if (WHITELIST[decryptedHwid]) {
    console.log(`Valid HWID: ${decryptedHwid}`);
    return res.status(200).json({ status: "VALID" });
  } else {
    console.log(`Invalid HWID: ${decryptedHwid}`);
    return res.status(403).json({ status: "ERROR", message: "Invalid HWID" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));