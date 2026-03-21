const crypto = require("crypto");
const nacl = require("tweetnacl");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const protobuf = require("protobufjs");

const AppError = require("../utils/appError");
const catchAsync = require("../utils/catchAsync");
const User = require("../models/UserModel");

// Minimal Hedera signature schema for decoding walletConnect hedera_signMessage output
const hederaSigProto = `
syntax = "proto3";
package proto;

message SignaturePair {
  bytes pubKeyPrefix = 1;
  oneof signature {
    bytes contract = 2;
    bytes ed25519 = 3;
    bytes RSA_3072 = 4;
    bytes ECDSA_384 = 5;
    bytes ECDSA_secp256k1 = 6;
  }
}

message SignatureMap {
  repeated SignaturePair sigPair = 1;
}
`;

const root = protobuf.parse(hederaSigProto).root;
const SignatureMap = root.lookupType("proto.SignatureMap");

function decodeSignatureMap(signatureMapB64, next) {
  const bytes = Buffer.from(signatureMapB64, "base64");
  const decoded = SignatureMap.decode(bytes);

  const pair = decoded.sigPair?.[0];
  if (!pair)
    return next(new AppError("No signature pair found in SignatureMap", 400));

  const signature = pair.ed25519 || pair.ECDSA_secp256k1;

  if (!signature) {
    return next(new AppError("No signature pair found in SignatureMap", 400));
  }

  return {
    type: pair.ed25519 ? "ed25519" : "ecdsa_secp256k1",
    signatureBytes: Uint8Array.from(signature),
    pubKeyPrefix: Uint8Array.from(pair.pubKeyPrefix || []),
  };
}

function buildHederaSignedMessage(message) {
  const prefix = "\x19Hedera Signed Message:\n";
  const length = Buffer.byteLength(message, "utf8");
  return Buffer.from(`${prefix}${length}${message}`, "utf8");
}

function hexToUint8Array(hex) {
  if (hex.startsWith("0x")) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

async function getAccountInfoFromMirror(accountId) {
  const base = "https://testnet.mirrornode.hedera.com"; // change to mainnet when needed
  const res = await fetch(`${base}/api/v1/accounts/${accountId}`);
  if (!res.ok) throw new Error("Mirror node lookup failed");
  return res.json();
}

// message: the exact string sent to wallet for signing
// signature: hex or base64 string
// accountId: "0.0.8123144"
async function verifySignedNonce(message, signatureMapB64, accountId, next) {
  const info = await getAccountInfoFromMirror(accountId);

  // Adjust this to match the exact Mirror Node JSON shape you receive.
  // The Hedera key type can be Ed25519 or ECDSA(secp256k1). :contentReference[oaicite:2]{index=2}
  const publicKeyHex = info.key?.key;
  if (!publicKeyHex) return next(new AppError("Public key not found", 400));

  const { type, signatureBytes } = decodeSignatureMap(signatureMapB64, next);
  const signedMessage = buildHederaSignedMessage(message);

  if (type !== "ed25519") {
    return next(
      new AppError(
        "This verifier currently supports only Ed25519 signatures",
        400,
      ),
    );
  }

  const messageBytes = new Uint8Array(signedMessage);
  const sigBytes = new Uint8Array(signatureBytes);
  const pubBytes = hexToUint8Array(publicKeyHex);

  if (sigBytes.length !== 64) {
    throw new Error(
      `Expected a 64-byte Ed25519 signature, got ${sigBytes.length}`,
    );
  }

  return nacl.sign.detached.verify(messageBytes, sigBytes, pubBytes);
}

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000,
    ),
    httpOnly: true,
  };
  if (process.env.NODE_ENV === "production") cookieOptions.secure = true;

  res.cookie("jwt", token, cookieOptions);

  // // Remove password from output
  // user.password = undefined;

  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      user,
    },
  });
};

exports.createNonce = function (nonces) {
  return catchAsync(async (req, res, next) => {
    const { accountId } = req.body;

    if (!accountId) {
      return next(new AppError("No address in request body", 400));
    }

    // Generate a unique cryptographically secure random string
    const nonce = crypto.randomBytes(16).toString("hex");
    const expires = Date.now() + 100 * 60 * 1000; // Expires in 5 min
    const account = accountId.toLowerCase();

    // Store it
    await fs.writeFile(
      `${__dirname}/../dev-data/nonces.json`,
      JSON.stringify({ ...nonces, [account]: { nonce, expires } }),
      (err) => {
        console.log(err);
      },
    );

    res.json({ nonce });
  });
};

exports.verifySignature = function (nonces) {
  return catchAsync(async (req, res, next) => {
    const { message, signature, accountId, nonce } = req.body;
    const savedNonce = nonces?.[accountId]?.["nonce"];
    const nonceTs = nonces?.[accountId]?.["expires"];

    if (!savedNonce || savedNonce !== nonce || nonceTs < Date.now()) {
      return next(new AppError("Invalid or expired nonce", 400));
    }

    const isVerified = await verifySignedNonce(
      message,
      signature,
      accountId,
      next,
    );
    if (!isVerified)
      return next(new AppError("Could not verify signature message", 400));
    const docs = await User.find({ accountId });

    let user;
    if (docs.length === 0) {
      user = await User.create({
        accountId,
      });
    } else {
      user = docs[0];
    }

    createSendToken(user, 201, res);
  });
};
