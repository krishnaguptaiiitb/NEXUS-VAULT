
const mongoose = require("mongoose");

const encryptedKeySchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    },

    // Legacy RSA-OAEP wrapped AES key.
    // Retained so existing files remain accessible.
    key: {
        type: String,
        default: null
    },

    // Version 1: legacy RSA envelope.
    // Version 2: X25519 + ML-KEM-768 hybrid envelope.
    envelopeVersion: {
        type: Number,
        default: 1
    },

    keyAlgorithm: {
        type: String,
        enum: [
            "RSA-OAEP-2048",
            "X25519-ML-KEM-768"
        ],
        default: "RSA-OAEP-2048"
    },

    // Ephemeral X25519 public key used for this envelope.
    x25519EphemeralPublicKey: {
        type: String,
        default: null
    },

    // ML-KEM-768 encapsulation ciphertext.
    mlkemCiphertext: {
        type: String,
        default: null
    },

    // HKDF salt for deriving the wrapping key.
    hkdfSalt: {
        type: String,
        default: null
    },

    // AES-GCM nonce used to wrap the file encryption key.
    wrappingNonce: {
        type: String,
        default: null
    },

    // AES-GCM encrypted file encryption key.
    wrappedKey: {
        type: String,
        default: null
    }
}, {
    _id: false
});

const fileSchema = new mongoose.Schema({
    filename: {
        type: String,
        required: true
    },

    encryptedPath: {
        type: String,
        required: true
    },

    encryptedKeys: {
        type: [encryptedKeySchema],
        default: []
    },

    // File encryption nonce/IV.
    iv: {
        type: String,
        required: true
    },

    encryptionAlgorithm: {
        type: String,
        enum: ["AES-CBC", "AES-GCM"],
        default: "AES-CBC"
    },

    hash: {
        type: String
    },

    signature: {
        type: String
    },

    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    }
}, {
    timestamps: true
});

const File = mongoose.model("File", fileSchema);

module.exports = File;
