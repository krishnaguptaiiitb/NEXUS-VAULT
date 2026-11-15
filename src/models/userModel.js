
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },

    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },

    password: {
        type: String,
        required: true
    },

    // Existing RSA public key.
    // Retained for compatibility with existing encrypted files.
    publicKey: {
        type: String
    },

    // X25519 public key, encoded as Base64.
    x25519PublicKey: {
        type: String,
        default: null
    },

    // ML-KEM-768 encapsulation public key, encoded as Base64.
    mlkem768PublicKey: {
        type: String,
        default: null
    },

    // Version of the hybrid key format.
    hybridKeyVersion: {
        type: Number,
        default: 0
    },

    // When the hybrid public keys were registered.
    hybridKeyCreatedAt: {
        type: Date,
        default: null
    }
}, {
    timestamps: true
});

const User = mongoose.model("User", userSchema);

module.exports = User;
