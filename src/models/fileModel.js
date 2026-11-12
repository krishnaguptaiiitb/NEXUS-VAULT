
const mongoose = require("mongoose");

const fileSchema = new mongoose.Schema({
    filename: String,
    path: String,
    encryptedPath: String,

    encryptedKeys: [
        {
            user: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User"
            },
            key: String
        }
    ],

    iv: String,

    encryptionAlgorithm: {
        type: String,
        enum: ["AES-CBC", "AES-GCM"],
        default: "AES-CBC"
    },

    hash: String,
    signature: String,

    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    }
});

const File = mongoose.model("File", fileSchema);

module.exports = File;
