
const fs = require("fs");
const crypto = require("crypto");
const mongoose = require("mongoose");

const File = require("../models/fileModel");
const User = require("../models/userModel");

// =====================================================
// CONSTANTS
// =====================================================

const LEGACY_ALGORITHM = "RSA-OAEP-2048";
const HYBRID_ALGORITHM = "X25519-ML-KEM-768";

const MAX_FILENAME_LENGTH = 255;
const MAX_ENVELOPE_FIELD_LENGTH = 16384;

// =====================================================
// GENERAL HELPERS
// =====================================================

const isValidObjectId = (id) => mongoose.Types.ObjectId.isValid(id);

const removeUploadedFile = (filePath) => {
    if (!filePath) return;

    try {
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
    } catch (error) {
        console.error("File cleanup error:", error.message);
    }
};

const isValidBase64 = (value, minBytes = 1, maxBytes = 16384) => {
    if (typeof value !== "string" || !value.length) {
        return false;
    }

    if (value.length > MAX_ENVELOPE_FIELD_LENGTH) {
        return false;
    }

    // Accept standard Base64 with optional padding.
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
        return false;
    }

    const buffer = Buffer.from(value, "base64");

    // Reject malformed or non-canonical Base64.
    const normalizedInput = value.replace(/=+$/, "");
    const normalizedOutput = buffer.toString("base64").replace(/=+$/, "");

    if (normalizedInput !== normalizedOutput) {
        return false;
    }

    return buffer.length >= minBytes && buffer.length <= maxBytes;
};

const isValidFixedBase64 = (value, expectedBytes) => {
    return isValidBase64(value, expectedBytes, expectedBytes) &&
        Buffer.from(value, "base64").length === expectedBytes;
};

const getAuthenticatedUserId = (req) => {
    return req.user?._id?.toString();
};

// =====================================================
// ENVELOPE VALIDATION
// =====================================================

/*
    Legacy envelope:
    {
        encryptedKey: "..."
    }

    Hybrid envelope:
    {
        envelopeVersion: 2,
        keyAlgorithm: "X25519-ML-KEM-768",
        x25519EphemeralPublicKey: "...",
        mlkemCiphertext: "...",
        hkdfSalt: "...",
        wrappingNonce: "...",
        wrappedKey: "..."
    }
*/

const getEnvelopeData = (body = {}) => {
    const {
        encryptedKey,
        envelopeVersion,
        keyAlgorithm,
        x25519EphemeralPublicKey,
        mlkemCiphertext,
        hkdfSalt,
        wrappingNonce,
        wrappedKey
    } = body;

    const hasLegacyKey = encryptedKey !== undefined &&
        encryptedKey !== null &&
        encryptedKey !== "";

    const hasHybridFields = [
        x25519EphemeralPublicKey,
        mlkemCiphertext,
        hkdfSalt,
        wrappingNonce,
        wrappedKey
    ].some((value) => value !== undefined && value !== null && value !== "");

    // Reject ambiguous requests containing both formats.
    if (hasLegacyKey && hasHybridFields) {
        return null;
    }

    // Legacy RSA-OAEP envelope.
    if (hasLegacyKey) {
        if (
            typeof encryptedKey !== "string" ||
            !isValidBase64(encryptedKey, 128, 1024)
        ) {
            return null;
        }

        return {
            key: encryptedKey,
            envelopeVersion: 1,
            keyAlgorithm: LEGACY_ALGORITHM
        };
    }

    // Hybrid X25519 + ML-KEM-768 envelope.
    if (
        Number(envelopeVersion) !== 2 ||
        keyAlgorithm !== HYBRID_ALGORITHM
    ) {
        return null;
    }

    /*
        Expected encoded values:

        X25519 raw public key: 32 bytes
        ML-KEM-768 ciphertext: 1088 bytes
        HKDF salt:             16 to 64 bytes
        AES-GCM nonce:         12 bytes
        Wrapped AES-256 key:   48 to 64 bytes

        A 32-byte AES key encrypted with AES-GCM
        normally produces 48 bytes including the tag.
    */

    if (!isValidFixedBase64(x25519EphemeralPublicKey, 32)) {
        return null;
    }

    if (!isValidFixedBase64(mlkemCiphertext, 1088)) {
        return null;
    }

    if (!isValidBase64(hkdfSalt, 16, 64)) {
        return null;
    }

    if (!isValidFixedBase64(wrappingNonce, 12)) {
        return null;
    }

    if (!isValidBase64(wrappedKey, 48, 64)) {
        return null;
    }

    return {
        key: null,
        envelopeVersion: 2,
        keyAlgorithm: HYBRID_ALGORITHM,
        x25519EphemeralPublicKey,
        mlkemCiphertext,
        hkdfSalt,
        wrappingNonce,
        wrappedKey
    };
};

// =====================================================
// ENVELOPE SERIALIZATION
// =====================================================

const serializeEnvelope = (keyObject) => ({
    encryptedKey: keyObject.key || null,
    envelopeVersion: keyObject.envelopeVersion || 1,
    keyAlgorithm: keyObject.keyAlgorithm || LEGACY_ALGORITHM,

    x25519EphemeralPublicKey:
        keyObject.x25519EphemeralPublicKey || null,

    mlkemCiphertext:
        keyObject.mlkemCiphertext || null,

    hkdfSalt:
        keyObject.hkdfSalt || null,

    wrappingNonce:
        keyObject.wrappingNonce || null,

    wrappedKey:
        keyObject.wrappedKey || null
});

// =====================================================
// FILE INTEGRITY
// =====================================================

const calculateSHA256 = (buffer) => {
    return crypto
        .createHash("sha256")
        .update(buffer)
        .digest("hex");
};

const verifyFileIntegrity = (buffer, expectedHash) => {
    // Older files without a stored hash remain accessible.
    if (!expectedHash) {
        return true;
    }

    if (
        typeof expectedHash !== "string" ||
        !/^[a-f0-9]{64}$/i.test(expectedHash)
    ) {
        return false;
    }

    const actualHash = calculateSHA256(buffer);

    const expected = Buffer.from(expectedHash, "hex");
    const actual = Buffer.from(actualHash, "hex");

    return crypto.timingSafeEqual(actual, expected);
};

// =====================================================
// UPLOAD FILE
// =====================================================

const uploadFile = async (req, res) => {
    const uploadedPath = req.file?.path;

    try {
        const { iv } = req.body;

        const encryptionAlgorithm =
            req.body.encryptionAlgorithm || "AES-CBC";

        const envelope = getEnvelopeData(req.body);

        if (!req.file) {
            return res.status(400).json({
                message: "No file uploaded"
            });
        }

        if (!iv || typeof iv !== "string") {
            return res.status(400).json({
                message: "File encryption IV is required"
            });
        }

        if (!envelope) {
            return res.status(400).json({
                message: "Missing or invalid encryption envelope"
            });
        }

        if (!["AES-CBC", "AES-GCM"].includes(encryptionAlgorithm)) {
            return res.status(400).json({
                message: "Unsupported encryption algorithm"
            });
        }

        if (
            !req.file.originalname ||
            req.file.originalname.length > MAX_FILENAME_LENGTH
        ) {
            return res.status(400).json({
                message: "Invalid filename"
            });
        }

        const userId = getAuthenticatedUserId(req);

        if (!userId) {
            return res.status(401).json({
                message: "Authentication required"
            });
        }

        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        const encryptedBuffer = fs.readFileSync(req.file.path);

        if (!encryptedBuffer.length) {
            return res.status(400).json({
                message: "Uploaded encrypted file is empty"
            });
        }

        const hash = calculateSHA256(encryptedBuffer);

        const savedFile = await File.create({
            filename: req.file.originalname,
            encryptedPath: req.file.path,

            encryptedKeys: [
                {
                    user: user._id,
                    ...envelope
                }
            ],

            iv,
            encryptionAlgorithm,
            hash,
            owner: user._id
        });

        return res.status(201).json(savedFile);

    } catch (error) {
        console.error("Upload error:", error.message);

        return res.status(500).json({
            message: "Upload failed"
        });

    } finally {
        // Remove temporary uploads if database saving failed.
        // Successfully saved files remain on disk.
        if (uploadedPath) {
            try {
                const saved = await File.exists({
                    encryptedPath: uploadedPath
                });

                if (!saved) {
                    removeUploadedFile(uploadedPath);
                }
            } catch (cleanupError) {
                console.error(
                    "Upload cleanup check failed:",
                    cleanupError.message
                );
            }
        }
    }
};

// =====================================================
// DOWNLOAD FILE
// =====================================================

const downloadFile = async (req, res) => {
    try {
        const fileId = req.params.id;

        if (!isValidObjectId(fileId)) {
            return res.status(400).json({
                message: "Invalid file ID"
            });
        }

        const file = await File.findById(fileId);

        if (!file) {
            return res.status(404).json({
                message: "File not found"
            });
        }

        const userId = getAuthenticatedUserId(req);

        const userKeyObj = file.encryptedKeys.find(
            (item) => item.user.toString() === userId
        );

        if (!userKeyObj) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        if (!fs.existsSync(file.encryptedPath)) {
            return res.status(404).json({
                message: "Encrypted file not found on server"
            });
        }

        const encryptedBuffer = fs.readFileSync(file.encryptedPath);

        if (!verifyFileIntegrity(encryptedBuffer, file.hash)) {
            return res.status(400).json({
                message: "File integrity verification failed"
            });
        }

        return res.status(200).json({
            encryptedData: encryptedBuffer.toString("base64"),

            ...serializeEnvelope(userKeyObj),

            iv: file.iv,
            encryptionAlgorithm: file.encryptionAlgorithm || "AES-CBC",
            filename: file.filename
        });

    } catch (error) {
        console.error("Download error:", error.message);

        return res.status(500).json({
            message: "Error downloading file"
        });
    }
};

// =====================================================
// SHARE FILE
// =====================================================

const shareFile = async (req, res) => {
    try {
        const { fileId, receiverId } = req.body;

        const envelope = getEnvelopeData(req.body);

        if (!fileId || !receiverId || !envelope) {
            return res.status(400).json({
                message: "Missing or invalid sharing information"
            });
        }

        if (!isValidObjectId(fileId) || !isValidObjectId(receiverId)) {
            return res.status(400).json({
                message: "Invalid file or receiver ID"
            });
        }

        const file = await File.findById(fileId);

        if (!file) {
            return res.status(404).json({
                message: "File not found"
            });
        }

        const currentUserId = getAuthenticatedUserId(req);

        if (file.owner.toString() !== currentUserId) {
            return res.status(403).json({
                message: "Only the file owner can share this file"
            });
        }

        const receiver = await User.findById(receiverId);

        if (!receiver) {
            return res.status(404).json({
                message: "Receiver not found"
            });
        }

        if (receiver._id.toString() === currentUserId) {
            return res.status(400).json({
                message: "You cannot share a file with yourself"
            });
        }

        if (
            envelope.envelopeVersion === 2 &&
            (!receiver.x25519PublicKey || !receiver.mlkem768PublicKey)
        ) {
            return res.status(400).json({
                message: "Receiver has not registered hybrid public keys"
            });
        }

        if (
            envelope.envelopeVersion === 1 &&
            !receiver.publicKey
        ) {
            return res.status(400).json({
                message: "Receiver has not registered an RSA public key"
            });
        }

        const alreadyShared = file.encryptedKeys.some(
            (item) => item.user.toString() === receiverId.toString()
        );

        if (alreadyShared) {
            return res.status(409).json({
                message: "File is already shared with this user"
            });
        }

        file.encryptedKeys.push({
            user: receiver._id,
            ...envelope
        });

        await file.save();

        const io = req.app.get("io");

        if (io) {
            io.to(`user:${receiverId}`).emit(
                "file-access-granted",
                {
                    fileId: file._id.toString(),
                    message: "A new file has been shared with you."
                }
            );
        }

        return res.status(200).json({
            message: "File shared successfully"
        });

    } catch (error) {
        console.error("Share error:", error.message);

        return res.status(500).json({
            message: "File sharing failed"
        });
    }
};

// =====================================================
// DELETE FILE
// =====================================================

const deleteFile = async (req, res) => {
    try {
        const fileId = req.params.id;

        if (!isValidObjectId(fileId)) {
            return res.status(400).json({
                message: "Invalid file ID"
            });
        }

        const file = await File.findById(fileId);

        if (!file) {
            return res.status(404).json({
                message: "File not found"
            });
        }

        const currentUserId = getAuthenticatedUserId(req);

        if (file.owner.toString() !== currentUserId) {
            return res.status(403).json({
                message: "Only the file owner can delete this file"
            });
        }

        const encryptedPath = file.encryptedPath;

        await file.deleteOne();

        removeUploadedFile(encryptedPath);

        return res.status(200).json({
            message: "File deleted successfully"
        });

    } catch (error) {
        console.error("Delete error:", error.message);

        return res.status(500).json({
            message: "Error deleting file"
        });
    }
};

// =====================================================
// REVOKE ACCESS
// =====================================================

const revokeAccess = async (req, res) => {
    try {
        const { fileId, userId } = req.body;

        if (!fileId || !userId) {
            return res.status(400).json({
                message: "File ID and recipient ID are required"
            });
        }

        if (!isValidObjectId(fileId) || !isValidObjectId(userId)) {
            return res.status(400).json({
                message: "Invalid file or recipient ID"
            });
        }

        const currentUserId = getAuthenticatedUserId(req);
        const targetUserId = userId.toString();

        if (targetUserId === currentUserId) {
            return res.status(400).json({
                message: "Owner cannot revoke their own access"
            });
        }

        const file = await File.findById(fileId);

        if (!file) {
            return res.status(404).json({
                message: "File not found"
            });
        }

        if (file.owner.toString() !== currentUserId) {
            return res.status(403).json({
                message: "Only the file owner can revoke access"
            });
        }

        const hasAccess = file.encryptedKeys.some(
            (item) => item.user.toString() === targetUserId
        );

        if (!hasAccess) {
            return res.status(404).json({
                message: "Recipient does not have access to this file"
            });
        }

        file.encryptedKeys = file.encryptedKeys.filter(
            (item) => item.user.toString() !== targetUserId
        );

        await file.save();

        const io = req.app.get("io");

        if (io) {
            io.to(`user:${targetUserId}`).emit(
                "file-access-revoked",
                {
                    fileId: file._id.toString(),
                    message: "The owner has revoked your access to this file."
                }
            );
        }

        return res.status(200).json({
            message: "Access revoked successfully",
            keyRotationRequired: true
        });

    } catch (error) {
        console.error("Revoke error:", error.message);

        return res.status(500).json({
            message: "Error revoking access"
        });
    }
};

// =====================================================
// GET USER FILES
// =====================================================

const getFiles = async (req, res) => {
    try {
        const userId = getAuthenticatedUserId(req);

        const files = await File.find({
            $or: [
                { owner: userId },
                { "encryptedKeys.user": userId }
            ]
        })
            .populate("encryptedKeys.user", "email name")
            .sort({ createdAt: -1 });

        const filteredFiles = files.map((file) => {
            const fileObject = file.toObject();

            const isOwner =
                file.owner.toString() === userId;

            if (!isOwner) {
                // Recipients receive only their own envelope.
                fileObject.encryptedKeys =
                    fileObject.encryptedKeys.filter((item) => {
                        const envelopeUserId =
                            item.user?._id?.toString() ||
                            item.user?.toString();

                        return envelopeUserId === userId;
                    });
            }

            return fileObject;
        });

        return res.status(200).json(filteredFiles);

    } catch (error) {
        console.error("Fetch files error:", error.message);

        return res.status(500).json({
            message: "Error fetching files"
        });
    }
};

// =====================================================
// GET FILE KEY
// =====================================================

const getFileKey = async (req, res) => {
    try {
        const fileId = req.params.id;

        if (!isValidObjectId(fileId)) {
            return res.status(400).json({
                message: "Invalid file ID"
            });
        }

        const file = await File.findById(fileId);

        if (!file) {
            return res.status(404).json({
                message: "File not found"
            });
        }

        const userId = getAuthenticatedUserId(req);

        const userKeyObj = file.encryptedKeys.find(
            (item) => item.user.toString() === userId
        );

        if (!userKeyObj) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        return res.status(200).json({
            ...serializeEnvelope(userKeyObj),
            iv: file.iv,
            encryptionAlgorithm: file.encryptionAlgorithm || "AES-CBC"
        });

    } catch (error) {
        console.error("Get file key error:", error.message);

        return res.status(500).json({
            message: "Error fetching key"
        });
    }
};

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
    uploadFile,
    downloadFile,
    getFiles,
    deleteFile,
    shareFile,
    revokeAccess,
    getFileKey
};
