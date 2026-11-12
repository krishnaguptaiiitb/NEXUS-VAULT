
const fs = require("fs");
const crypto = require("crypto");
const File = require("../models/fileModel");
const User = require("../models/userModel");

// ================= UPLOAD =================
const uploadFile = async (req, res) => {
    try {
        const { encryptedKey, iv } = req.body;
        const encryptionAlgorithm =
            req.body.encryptionAlgorithm || "AES-CBC";

        if (!encryptedKey || !iv) {
            return res.status(400).json({
                message: "Missing encryption data"
            });
        }

        if (!["AES-CBC", "AES-GCM"].includes(encryptionAlgorithm)) {
            return res.status(400).json({
                message: "Unsupported encryption algorithm"
            });
        }

        const file = req.file;

        if (!file) {
            return res.status(400).json({
                message: "No file uploaded"
            });
        }

        const user = await User.findById(req.user._id);

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        const encryptedBuffer = fs.readFileSync(file.path);

        const hash = crypto
            .createHash("sha256")
            .update(encryptedBuffer)
            .digest("hex");

        const savedFile = await File.create({
            filename: file.originalname,
            encryptedPath: file.path,
            encryptedKeys: [
                {
                    user: user._id,
                    key: encryptedKey
                }
            ],
            iv,
            encryptionAlgorithm,
            hash,
            owner: user._id
        });

        return res.status(200).json(savedFile);

    } catch (error) {
        console.error("Upload error:", error);

        return res.status(500).json({
            message: "Upload failed"
        });
    }
};

// ================= DOWNLOAD =================
const downloadFile = async (req, res) => {
    try {
        const file = await File.findById(req.params.id);

        if (!file) {
            return res.status(404).json({
                message: "File not found"
            });
        }

        const userId = req.user._id.toString();

        const userKeyObj = file.encryptedKeys.find(
            k => k.user.toString() === userId
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

        const newHash = crypto
            .createHash("sha256")
            .update(encryptedBuffer)
            .digest("hex");

        if (newHash !== file.hash) {
            return res.status(400).json({
                message: "File integrity verification failed"
            });
        }

        return res.json({
            encryptedData: encryptedBuffer.toString("base64"),
            encryptedKey: userKeyObj.key,
            iv: file.iv,
            encryptionAlgorithm: file.encryptionAlgorithm || "AES-CBC",
            filename: file.filename
        });

    } catch (error) {
        console.error("Download error:", error);

        return res.status(500).json({
            message: "Error downloading file"
        });
    }
};

// ================= SHARE =================
const shareFile = async (req, res) => {
    try {
        const { fileId, encryptedKey, receiverId } = req.body;

        if (!fileId || !encryptedKey || !receiverId) {
            return res.status(400).json({
                message: "Missing sharing information"
            });
        }

        const file = await File.findById(fileId);

        if (!file) {
            return res.status(404).json({
                message: "File not found"
            });
        }

        if (file.owner.toString() !== req.user._id.toString()) {
            return res.status(403).json({
                message: "Only owner can share"
            });
        }

        const receiver = await User.findById(receiverId);

        if (!receiver) {
            return res.status(404).json({
                message: "Receiver not found"
            });
        }

        if (receiver._id.toString() === req.user._id.toString()) {
            return res.status(400).json({
                message: "You cannot share a file with yourself"
            });
        }

        const alreadyShared = file.encryptedKeys.some(
            k => k.user.toString() === receiverId
        );

        if (alreadyShared) {
            return res.status(400).json({
                message: "File is already shared with this user"
            });
        }

        file.encryptedKeys.push({
            user: receiverId,
            key: encryptedKey
        });

        await file.save();

        // Notify all connected devices of the recipient
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

        return res.json({
            message: "Shared successfully"
        });

    } catch (error) {
        console.error("Share error:", error);

        return res.status(500).json({
            message: "Share failed"
        });
    }
};

// ================= DELETE =================
const deleteFile = async (req, res) => {
    try {
        const file = await File.findById(req.params.id);

        if (!file) {
            return res.status(404).json({
                message: "File not found"
            });
        }

        if (file.owner.toString() !== req.user._id.toString()) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        if (fs.existsSync(file.encryptedPath)) {
            fs.unlinkSync(file.encryptedPath);
        }

        await file.deleteOne();

        return res.json({
            message: "File deleted successfully"
        });

    } catch (error) {
        console.error("Delete error:", error);

        return res.status(500).json({
            message: "Error deleting file"
        });
    }
};

// ================= REVOKE =================
const revokeAccess = async (req, res) => {
    try {
        const { fileId, userId } = req.body;

        if (!fileId || !userId) {
            return res.status(400).json({
                message: "Missing file or user information"
            });
        }

        const currentUserId = req.user._id.toString();
        const targetUserId = userId.toString();

        // Prevent owner from revoking their own access
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

        // Only the owner can revoke access
        if (file.owner.toString() !== currentUserId) {
            return res.status(403).json({
                message: "Only owner can revoke access"
            });
        }

        // Check whether recipient currently has access
        const hasAccess = file.encryptedKeys.some(
            k => k.user.toString() === targetUserId
        );

        if (!hasAccess) {
            return res.status(404).json({
                message: "Recipient does not have access to this file"
            });
        }

        // Remove recipient's encrypted key
        file.encryptedKeys = file.encryptedKeys.filter(
            k => k.user.toString() !== targetUserId
        );

        await file.save();

        // Send real-time notification to all recipient devices
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

        return res.json({
            message: "Access revoked successfully"
        });

    } catch (error) {
        console.error("Revoke error:", error);

        return res.status(500).json({
            message: "Error revoking access"
        });
    }
};

// ================= GET FILES =================
const getFiles = async (req, res) => {
    try {
        const userId = req.user._id;

        const files = await File.find({
            $or: [
                { owner: userId },
                { "encryptedKeys.user": userId }
            ]
        }).populate("encryptedKeys.user", "email name");

        return res.json(files);

    } catch (error) {
        console.error("Fetch files error:", error);

        return res.status(500).json({
            message: "Error fetching files"
        });
    }
};

// ================= GET FILE KEY =================
const getFileKey = async (req, res) => {
    try {
        const file = await File.findById(req.params.id);

        if (!file) {
            return res.status(404).json({
                message: "File not found"
            });
        }

        const userId = req.user._id.toString();

        const userKeyObj = file.encryptedKeys.find(
            k => k.user.toString() === userId
        );

        if (!userKeyObj) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        return res.json({
            encryptedKey: userKeyObj.key,
            iv: file.iv,
            encryptionAlgorithm: file.encryptionAlgorithm || "AES-CBC"
        });

    } catch (error) {
        console.error("Get file key error:", error);

        return res.status(500).json({
            message: "Error fetching key"
        });
    }
};

module.exports = {
    uploadFile,
    downloadFile,
    getFiles,
    deleteFile,
    shareFile,
    revokeAccess,
    getFileKey
};
