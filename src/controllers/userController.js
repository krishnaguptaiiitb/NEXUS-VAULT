
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// =====================================================
// CONSTANTS
// =====================================================

const SALT_ROUNDS = 12;

const X25519_PUBLIC_KEY_BYTES = 32;
const MLKEM768_PUBLIC_KEY_BYTES = 1184;

const MAX_NAME_LENGTH = 100;
const MAX_EMAIL_LENGTH = 254;
const MAX_PASSWORD_LENGTH = 128;

// =====================================================
// GENERAL HELPERS
// =====================================================

const generateToken = (id) => {
    if (!process.env.JWT_SECRET) {
        throw new Error("JWT_SECRET is not configured");
    }

    return jwt.sign(
        { id: id.toString() },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
    );
};

const normalizeEmail = (email) => {
    if (typeof email !== "string") {
        return null;
    }

    const normalized = email.trim().toLowerCase();

    if (
        !normalized ||
        normalized.length > MAX_EMAIL_LENGTH ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)
    ) {
        return null;
    }

    return normalized;
};

const isValidBase64Key = (value, expectedBytes) => {
    if (typeof value !== "string" || !value.length) {
        return false;
    }

    // Base64 length should be reasonable for the expected key size.
    const maxEncodedLength = Math.ceil(expectedBytes / 3) * 4;

    if (value.length > maxEncodedLength + 4) {
        return false;
    }

    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
        return false;
    }

    const buffer = Buffer.from(value, "base64");

    const normalizedInput = value.replace(/=+$/, "");
    const normalizedOutput = buffer.toString("base64").replace(/=+$/, "");

    return (
        normalizedInput === normalizedOutput &&
        buffer.length === expectedBytes
    );
};

const validateHybridPublicKeys = (
    x25519PublicKey,
    mlkem768PublicKey
) => {
    return (
        isValidBase64Key(
            x25519PublicKey,
            X25519_PUBLIC_KEY_BYTES
        ) &&
        isValidBase64Key(
            mlkem768PublicKey,
            MLKEM768_PUBLIC_KEY_BYTES
        )
    );
};

// Return only public key material.
const getPublicKeyData = (user) => ({
    publicKey: user.publicKey || null,
    x25519PublicKey: user.x25519PublicKey || null,
    mlkem768PublicKey: user.mlkem768PublicKey || null,
    hybridKeyVersion: user.hybridKeyVersion || 0,
    hybridKeyCreatedAt: user.hybridKeyCreatedAt || null
});

const getSafeUserData = (user) => ({
    _id: user._id,
    name: user.name,
    email: user.email,
    ...getPublicKeyData(user)
});

// =====================================================
// REGISTER
// =====================================================

/*
    New registration request should contain:

    {
        name,
        email,
        password,
        publicKey,
        x25519PublicKey,
        mlkem768PublicKey
    }

    Hybrid public keys are saved in the same database
    operation as account creation.

    The hybrid fields remain optional temporarily
    for compatibility with existing clients.
*/

const registerUser = async (req, res) => {
    try {
        const {
            name,
            email,
            password,
            publicKey,
            x25519PublicKey,
            mlkem768PublicKey
        } = req.body || {};

        // Basic account validation.
        if (
            typeof name !== "string" ||
            !name.trim() ||
            typeof password !== "string" ||
            !password
        ) {
            return res.status(400).json({
                message: "Name, email and password are required"
            });
        }

        const normalizedName = name.trim();
        const normalizedEmail = normalizeEmail(email);

        if (!normalizedEmail) {
            return res.status(400).json({
                message: "Please provide a valid email address"
            });
        }

        if (normalizedName.length > MAX_NAME_LENGTH) {
            return res.status(400).json({
                message: "Name is too long"
            });
        }

        if (
            password.length < 8 ||
            password.length > MAX_PASSWORD_LENGTH
        ) {
            return res.status(400).json({
                message: "Password must be between 8 and 128 characters"
            });
        }

        if (
            publicKey !== undefined &&
            publicKey !== null &&
            (
                typeof publicKey !== "string" ||
                !publicKey.trim() ||
                publicKey.length > 8192
            )
        ) {
            return res.status(400).json({
                message: "Invalid RSA public key"
            });
        }

        // Both hybrid keys must be supplied together.
        const hasX25519Key =
            typeof x25519PublicKey === "string" &&
            x25519PublicKey.trim().length > 0;

        const hasMLKEMKey =
            typeof mlkem768PublicKey === "string" &&
            mlkem768PublicKey.trim().length > 0;

        if (hasX25519Key !== hasMLKEMKey) {
            return res.status(400).json({
                message: "Both hybrid public keys must be supplied together"
            });
        }

        if (
            hasX25519Key &&
            !validateHybridPublicKeys(
                x25519PublicKey.trim(),
                mlkem768PublicKey.trim()
            )
        ) {
            return res.status(400).json({
                message: "Invalid X25519 or ML-KEM-768 public key encoding"
            });
        }

        const userExists = await User.findOne({
            email: normalizedEmail
        });

        if (userExists) {
            return res.status(409).json({
                message: "User already exists"
            });
        }

        const hashedPassword = await bcrypt.hash(
            password,
            SALT_ROUNDS
        );

        const userData = {
            name: normalizedName,
            email: normalizedEmail,
            password: hashedPassword,
            publicKey: publicKey ? publicKey.trim() : null
        };

        // Save hybrid keys atomically with account creation.
        if (hasX25519Key) {
            userData.x25519PublicKey = x25519PublicKey.trim();
            userData.mlkem768PublicKey = mlkem768PublicKey.trim();
            userData.hybridKeyVersion = 1;
            userData.hybridKeyCreatedAt = new Date();
        }

        const user = await User.create(userData);

        return res.status(201).json({
            ...getSafeUserData(user),
            token: generateToken(user._id)
        });

    } catch (error) {
        // Handles duplicate email requests that race
        // between the initial lookup and database creation.
        if (error.code === 11000) {
            return res.status(409).json({
                message: "User already exists"
            });
        }

        console.error("Registration error:", error.message);

        return res.status(500).json({
            message: "Server error during registration"
        });
    }
};

// =====================================================
// REGISTER OR UPDATE HYBRID PUBLIC KEYS
// =====================================================

/*
    Retained for compatibility.

    When the public keys actually change, the version
    increases. Re-registering identical keys does not
    unnecessarily increment the version.
*/

const updateHybridPublicKeys = async (req, res) => {
    try {
        const {
            x25519PublicKey,
            mlkem768PublicKey
        } = req.body || {};

        if (
            typeof x25519PublicKey !== "string" ||
            typeof mlkem768PublicKey !== "string"
        ) {
            return res.status(400).json({
                message: "Both hybrid public keys are required"
            });
        }

        const normalizedX25519 = x25519PublicKey.trim();
        const normalizedMLKEM = mlkem768PublicKey.trim();

        if (
            !validateHybridPublicKeys(
                normalizedX25519,
                normalizedMLKEM
            )
        ) {
            return res.status(400).json({
                message: "Invalid X25519 or ML-KEM-768 public key encoding"
            });
        }

        const user = await User.findById(req.user._id);

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        const keysChanged =
            user.x25519PublicKey !== normalizedX25519 ||
            user.mlkem768PublicKey !== normalizedMLKEM;

        if (keysChanged) {
            user.x25519PublicKey = normalizedX25519;
            user.mlkem768PublicKey = normalizedMLKEM;

            user.hybridKeyVersion =
                (user.hybridKeyVersion || 0) + 1;

            user.hybridKeyCreatedAt = new Date();

            await user.save();
        }

        return res.status(200).json({
            message: "Hybrid public keys registered successfully",
            ...getPublicKeyData(user)
        });

    } catch (error) {
        console.error(
            "Hybrid key registration error:",
            error.message
        );

        return res.status(500).json({
            message: "Unable to register hybrid public keys"
        });
    }
};

// =====================================================
// GET USER BY EMAIL
// =====================================================

const getUserByEmail = async (req, res) => {
    try {
        const email = normalizeEmail(req.body?.email);

        if (!email) {
            return res.status(400).json({
                message: "Valid email is required"
            });
        }

        const user = await User.findOne({
            email
        }).select(
            "_id name email publicKey x25519PublicKey mlkem768PublicKey hybridKeyVersion hybridKeyCreatedAt"
        );

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        return res.status(200).json(
            getSafeUserData(user)
        );

    } catch (error) {
        console.error("Get user error:", error.message);

        return res.status(500).json({
            message: "Error fetching user"
        });
    }
};

// =====================================================
// LOGIN
// =====================================================

const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body || {};

        const normalizedEmail = normalizeEmail(email);

        if (
            !normalizedEmail ||
            typeof password !== "string" ||
            !password
        ) {
            return res.status(400).json({
                message: "Valid email and password are required"
            });
        }

        const user = await User.findOne({
            email: normalizedEmail
        });

        if (!user) {
            return res.status(401).json({
                message: "Invalid credentials"
            });
        }

        const isMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!isMatch) {
            return res.status(401).json({
                message: "Invalid credentials"
            });
        }

        return res.status(200).json({
            ...getSafeUserData(user),
            token: generateToken(user._id)
        });

    } catch (error) {
        console.error("Login error:", error.message);

        return res.status(500).json({
            message: "Server error during login"
        });
    }
};

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
    registerUser,
    loginUser,
    getUserByEmail,
    updateHybridPublicKeys
};
