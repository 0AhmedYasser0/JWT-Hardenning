
````markdown


## 🧐 Vulnerabilities Identified and Addressed

The original server (`vuln-server.js`) contained several critical weaknesses. Understanding these vulnerabilities is the first step toward securing any system.

### 1. Hard-coded Secrets
* **The Problem**: The JWT secret key (`WEAK_SECRET`) was written directly in the source code. If the code were ever leaked (e.g., mistakenly pushed to a public GitHub repository), anyone could see the key and forge any token they want.
* **The Solution**: Separating configuration and secrets from the code using `.env` files.

### 2. `alg:none` Vulnerability
* **The Problem**: The `/admin` endpoint was designed to blindly trust any token whose header claimed the algorithm was `none`. This allows an attacker to create a token with admin privileges, remove the signature, and send it to the server, which would accept it without any verification.
* **The Solution**: Enforcing the mandatory use of a strong cryptographic algorithm (`HS256`) when verifying any token.

### 3. Long-Lived Access Tokens
* **The Problem**: The access token was valid for **7 days**. If an attacker managed to steal this token (e.g., via an XSS attack), they could impersonate the victim for an entire week.
* **The Solution**: Shortening the access token's lifespan to just **15 minutes**.

### 4. Insecure Token Storage
* **The Problem**: The original application's design required the front-end to store the token in `localStorage`. Any JavaScript code running on the page (including malicious scripts injected via XSS) can read everything in `localStorage` and easily steal the token.
* **The Solution**: Implementing the "Refresh Token" pattern and storing its sensitive part in an **`HttpOnly` cookie**.

### 5. Missing Claim Validation
* **The Problem**: The server wasn't validating important claims like `iss` (issuer) and `aud` (audience).
* **The Solution**: Adding mandatory validation for these claims every time a token is verified.

### 6. No Refresh Token Strategy
* **The Problem**: Without a mechanism to renew the session, the only option was to use long-lived access tokens, which leads to problem #3.
* **The Solution**: Building a complete system based on a short-lived access token and a securely stored, long-lived refresh token.

---

## 🛡️ Security Hardening Steps Implemented in Detail

To fix the above vulnerabilities, we applied the following enhancements to `secure-server.js`.

### 1. Externalizing Configuration with `.env`
To solve the **hard-coded secrets** problem, we installed the `dotenv` library and separated all sensitive variables.
* **Action**: We created a `.env` file to store the actual secrets and a `.env.example` file as a template.
* **Result**: The code is now clean and secure. The application can be run in different environments with different settings without changing the code.

### 2. Implementing the Secure Token Pattern (Access + Refresh Tokens)

This is the most significant architectural change, solving the problems of **insecure storage** and **long-lived tokens**.
* **Access Token**: This is a short-lived "daily pass" (15 minutes). It's sent with every request to access protected resources.
* **Refresh Token**: This is a long-lived "ID card" (7 days). Its sole purpose is to get a new "daily pass" when the old one expires. The most critical part is that we store it in an **`HttpOnly` cookie**.
    * **Why `HttpOnly`?**: This flag prevents JavaScript from reading the cookie, providing strong protection against XSS attacks that aim to steal tokens.

### 3. Building a Central Authentication Middleware
Instead of repeating verification code in every route, we created an `authMiddleware` function to act as a "gatekeeper" for all protected endpoints.
* **Strict Verification**: This function uses `jwt.verify` to perform a comprehensive check that includes:
    1.  **Signature Verification**: Ensures the token has not been tampered with.
    2.  **Algorithm Verification**: Enforces the use of `HS256` only. This is the **direct solution to the `alg:none` vulnerability**.
    3.  **Expiration Check**: Ensures the token has not expired.
    4.  **Claim Validation**: Ensures the `issuer` and `audience` match what is expected.

### 4. Correcting Authorization Logic in Token Refresh
* **The Discovered Bug**: The `/refresh` endpoint had a critical logic error; it always issued a new access token with the role hard-coded to `'user'`, even if the user requesting the refresh was an `admin`.
* **The Fix**: We modified `/refresh` to **query the database for the user's current and correct role** before issuing a new token. This ensures permissions remain accurate at all times.

---

## 🚀 How to Run

### 1. Prerequisites
* Node.js (v18+)
* npm

### 2. Installation
```bash
# Clone the repository
git clone <your-repo-url>
cd <repo-folder>

# Install dependencies
npm install
````

### 3\. Configuration

Copy the example environment file and fill it with your own secret values. **Use a secure random string generator for the secrets.**

```bash
cp .env.example .env
```

Now, open the `.env` file and add the secrets you generated.

### 4\. Initialize the Database

This command creates the `users.db` file and populates it with sample users (`admin`/`adminpass` and `alice`/`alicepass`).

```bash
npm run init-db
```

### 5\. Run the Servers

You can run both servers simultaneously on different ports.

```bash
# Start the vulnerable server on http://localhost:1234
npm run start-vuln

# Start the secure server on http://localhost:1235
npm run start-secure
```

-----

## 💥 Demonstrating the `alg:none` Attack

### 1\. Attacking the Vulnerable Server (Successful ✅)

Use `curl` or Postman to send a forged, unsigned token. The token consists of only two parts (header and payload) separated by a dot.

  * **Header**: `{"alg":"none","typ":"JWT"}`
  * **Payload**: `{"sub":"hacker","role":"admin"}`

<!-- end list -->

```bash
curl -X GET http://localhost:1234/admin \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJoYWNrZXIiLCJyb2xlIjoiYWRtaW4ifQ."
```

**Expected Result**: You will successfully retrieve the sensitive data because the vulnerable server has an `if` condition that allows this type of token to pass.

### 2\. Attacking the Hardened Server (Fails ❌)

Execute the **exact same command** but target the secure server on port `1235`.

```bash
curl -X GET http://localhost:1235/admin \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJoYWNrZXIiLCJyb2xlIjoiYWRtaW4ifQ."
```

**Expected Result**: The request will be rejected with a **`401 Unauthorized`** error. This is because our `authMiddleware` enforces verification using only the `HS256` algorithm, and anything else (including `none`) will fail immediately.

-----

## 🕵️‍♂️ Traffic Analysis with Wireshark

This section explains how to see the token being sent over the network, highlighting the importance of using HTTPS.

1.  **Start Capture**: Open Wireshark and begin capturing on your local loopback interface.
2.  **Filter Traffic**: To easily find the requests, use a display filter like `http.request.method == "POST" && tcp.port == 1235`.
3.  **Perform Login**: Use the front-end UI to log in to the secure server (`localhost:1235`).
4.  **Inspect the Packet**:
      * Find the `POST /login` packet in the Wireshark list.
      * In the "Packet Details" pane below, expand the "Hypertext Transfer Protocol" section.
      * You will see the `Authorization: Bearer <JWT_TOKEN...>` header in plain, readable text.
      * **Conclusion**: This proves that anyone on the same network (e.g., at a coffee shop) can see the token if the connection is not encrypted. This is why **using HTTPS is mandatory and non-negotiable** in any real-world application.

<!-- end list -->

```
```
