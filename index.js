const express = require("express");
const session = require("express-session");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const querystring = require("querystring");
const forge = require("node-forge");

const PORT = 8000;
const FORUM_URL = "https://forum.cfx.re";
const REDIRECT_URL = `http://localhost:${PORT}`;
const APPLICATION_NAME = "APP_NAME";
const PADDING = "RSAES-PKCS1-V1_5";

const app = express();

app.use(
  session({
    secret: "replace_with_a_strong_secret",
    resave: false,
    saveUninitialized: true
  })
);

const privateKeyPem = fs.readFileSync("keypair.pem", "utf8");
const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

app.get("/", async (req, res) => {
  if (!req.query.payload) {
    const publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);
    const publicKeyPem = forge.pki.publicKeyToPem(publicKey);

    const nonce = crypto.randomBytes(16).toString("hex");
    const clientId = crypto.randomBytes(48).toString("hex");
    req.session.nonce = nonce;
    req.session.clientId = clientId;

    const params = {
      auth_redirect: REDIRECT_URL,
      application_name: APPLICATION_NAME,
      scopes: "session_info",
      client_id: clientId,
      nonce,
      public_key: publicKeyPem
    };

    const url = `${FORUM_URL}/user-api-key/new?${querystring.stringify(params)}`;
    return res.redirect(url);
  }

  const payloadBuf = Buffer.from(req.query.payload, "base64");
  let decrypted;
  try {
    decrypted = privateKey.decrypt(payloadBuf.toString("binary"), PADDING);
  } catch (e) {
    console.error("Decrypt error:", e);
    return res.status(500).send("Failed to decrypt payload");
  }

  let response;
  try {
    response = JSON.parse(decrypted);
  } catch (e) {
    return res.status(500).send("Invalid payload data");
  }

  if (response.nonce !== req.session.nonce) {
    return res.status(400).send("Invalid nonce");
  }

  const apiKey = response.key;
  try {
    const { data } = await axios.get(`${FORUM_URL}/session/current.json`, {
      headers: {
        "User-Api-Key": apiKey,
        "User-Api-Client-Id": req.session.clientId
      }
    });
    res.send(`<pre>${JSON.stringify(data.current_user, null, 2)}</pre>`);
  } catch (e) {
    res.status(500).send("Failed to fetch session");
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on ${REDIRECT_URL}`);
});
