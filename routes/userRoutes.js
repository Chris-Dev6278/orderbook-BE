const express = require("express");
const fs = require("fs");
const authController = require("../controllers/authController");

const router = express.Router();

const nonces = JSON.parse(
  fs.readFileSync(`${__dirname}/../dev-data/nonces.json`, "utf-8"),
);

router.post("/create-nonce", authController.createNonce(nonces));
router.post("/verify-signature", authController.verifySignature(nonces));

module.exports = router;
