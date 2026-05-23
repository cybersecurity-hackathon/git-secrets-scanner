// ============================================================
// JWT Authentication Configuration
// ============================================================
// WARNING: This file intentionally contains fake signing keys
// for testing the GitSentinel secrets detection scanner.
// None of these keys are used in any real authentication system.
// ============================================================

const crypto = require('crypto');

// Primary JWT configuration
const jwtConfig = {
    // HMAC signing secret — an attacker with this can forge ANY user token
    JWT_SECRET: "mySuperSecretJWTKey2024!@#$%^&*()_+LongEnoughToBeHighEntropy",
    JWT_EXPIRY: "24h",
    JWT_ALGORITHM: "HS256",
    JWT_ISSUER: "vulnerable-app",
    JWT_AUDIENCE: "vulnerable-app-users",
};

// Signing key for refresh tokens (separate from access tokens)
const REFRESH_TOKEN_SECRET = "RefreshT0ken$ecret_N3ver$hare!X9f2kL8pW3mQ7v";

// API signing key for webhook verification
const signing_key = "wh00k_s1gn1ng_k3y_2024_s3cur3_v@lu3_abc123def456";

// Session encryption key
const SESSION_SECRET = "s3ss10n_3ncrypt10n_k3y_pr0duct10n_2024!@#";

/**
 * Generate a signed JWT token for the given user payload.
 * @param {Object} payload - User data to encode
 * @returns {string} Signed JWT token
 */
function generateToken(payload) {
    const jwt = require('jsonwebtoken');
    return jwt.sign(payload, jwtConfig.JWT_SECRET, {
        expiresIn: jwtConfig.JWT_EXPIRY,
        algorithm: jwtConfig.JWT_ALGORITHM,
        issuer: jwtConfig.JWT_ISSUER,
    });
}

/**
 * Verify and decode a JWT token.
 * @param {string} token - The JWT token to verify
 * @returns {Object} Decoded payload
 */
function verifyToken(token) {
    const jwt = require('jsonwebtoken');
    return jwt.verify(token, jwtConfig.JWT_SECRET, {
        algorithms: [jwtConfig.JWT_ALGORITHM],
        issuer: jwtConfig.JWT_ISSUER,
    });
}

module.exports = { jwtConfig, generateToken, verifyToken };
