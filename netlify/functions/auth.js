import jwt from "jsonwebtoken";
import fetch from "node-fetch";

export async function handler(event) {
  const { authorization } = event.headers;
  if (!authorization) {
    return {
      statusCode: 401,
      body: JSON.stringify({ error: "Missing Authorization header" }),
    };
  }

  try {
    // Extract token
    const token = authorization.split(" ")[1];

    // Decode token
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) throw new Error("Invalid token");

    // Verify token with Auth0
    const auth0Domain = "dev-0wyo82izwfochqny.us.auth0.com"; // Example: your-tenant.auth0.com
    const jwksUrl = `https://${auth0Domain}/.well-known/jwks.json`;

    const response = await fetch(jwksUrl);
    const { keys } = await response.json();

    const signingKey = keys.find((key) => key.kid === decoded.header.kid);
    if (!signingKey) throw new Error("Invalid signing key");

    const verifiedToken = jwt.verify(token, signingKey.x5c[0], { algorithms: ["RS256"] });

    // Optional: Check if user is allowed to access DecapCMS
    if (!verifiedToken.email.endsWith("@kps3.com")) {
      return {
        statusCode: 403,
        body: JSON.stringify({ error: "Access denied" }),
      };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ token: verifiedToken }),
    };
  } catch (error) {
    return {
      statusCode: 401,
      body: JSON.stringify({ error: "Invalid token" }),
    };
  }
}
