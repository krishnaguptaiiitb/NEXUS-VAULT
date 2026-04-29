const fs = require("fs");
const crypto = require("crypto");
const File = require("../models/fileModel");
const User = require("../models/userModel");

// ================= UPLOAD =================
const uploadFile = async (req, res) => {
    try {
        const { encryptedKey, iv } = req.body;
        if (!encryptedKey || !iv) {
            return res.status(400).json({ message: "Missing encryption data" });
        }
        
        const file = req.file;

        const user = await User.findById(req.user._id);

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
            hash,
            owner: user._id
        });

        res.status(200).json(savedFile);

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Upload failed" });
    }
};

// ================= DOWNLOAD =================
const downloadFile = async (req, res) => {
    try {
        const file = await File.findById(req.params.id);

        if (!file) {
            return res.status(404).json({ message: "File not found" });
        }

        const userId = req.user._id.toString();

        const userKeyObj = file.encryptedKeys.find(
            k => k.user.toString() === userId
        );

        if (!userKeyObj) {
            return res.status(403).json({ message: "Access denied" });
        }

        // 🔥 VERIFY HASH ONLY
        const encryptedBuffer = fs.readFileSync(file.encryptedPath);

        const newHash = crypto
            .createHash("sha256")
            .update(encryptedBuffer)
            .digest("hex");

        if (newHash !== file.hash) {
            return res.status(400).json({ message: "File tampered ❌" });
        }

        // 🔐 SEND DATA TO FRONTEND (NO DECRYPTION HERE)
        res.json({
            encryptedData: encryptedBuffer.toString("base64"),
            encryptedKey: userKeyObj.key,
            iv: file.iv,
            filename: file.filename
        });

    } catch (error) {
        res.status(500).json({ message: "Error downloading file" });
    }
};

// ================= SHARE =================
// ⚠️ TEMP DISABLED (will move to frontend later)
const shareFile = async (req, res) => {
    try {
        const { fileId, encryptedKey, receiverId } = req.body;

        const file = await File.findById(fileId);

        if (file.owner.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: "Only owner can share" });
        }

        file.encryptedKeys.push({
            user: receiverId,
            key: encryptedKey
        });

        await file.save();

        res.json({ message: "Shared successfully 🔐" });

    } catch (error) {
        res.status(500).json({ message: "Share failed" });
    }
};

// ================= DELETE =================
const deleteFile = async (req, res) => {
    try {
        const file = await File.findById(req.params.id);

        if (!file) {
            return res.status(404).json({ message: "File not found" });
        }

        if (file.owner.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: "Access denied" });
        }

        fs.unlink(file.encryptedPath, (err) => {
            if (err) console.error("File delete error:", err);
        });

        await file.deleteOne();

        res.json({ message: "File deleted successfully ✅" });

    } catch (error) {
        res.status(500).json({ message: "Error deleting file" });
    }
};

// ================= REVOKE =================
const revokeAccess = async (req, res) => {
    try {
        const { fileId, userId } = req.body;

        const file = await File.findById(fileId);

        if (!file) {
            return res.status(404).json({ message: "File not found" });
        }

        if (file.owner.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: "Only owner can revoke access" });
        }

        file.encryptedKeys = file.encryptedKeys.filter(
            k => k.user.toString() !== userId
        );

        await file.save();

        res.json({ message: "Access revoked successfully ✅" });

    } catch (error) {
        res.status(500).json({ message: "Error revoking access" });
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

        res.json(files);
    } catch (error) {
        res.status(500).json({ message: "Error fetching files" });
    }
};

const getFileKey = async (req, res) => {
    try {
        const file = await File.findById(req.params.id);

        const userId = req.user._id.toString();

        const userKeyObj = file.encryptedKeys.find(
            k => k.user.toString() === userId
        );

        if (!userKeyObj) {
            return res.status(403).json({ message: "Access denied" });
        }

        res.json({
            encryptedKey: userKeyObj.key,
            iv: file.iv
        });

    } catch (error) {
        res.status(500).json({ message: "Error fetching key" });
    }
};

module.exports = { uploadFile, downloadFile, getFiles, deleteFile, shareFile, revokeAccess, getFileKey };