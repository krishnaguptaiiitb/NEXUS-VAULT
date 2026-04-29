const express = require("express");
const { uploadFile, downloadFile, getFiles, deleteFile, shareFile, revokeAccess, getFileKey } = require("../controllers/fileController");
const upload = require("../utils/upload");
const protect = require("../middleware/authMiddleware");

const router = express.Router();

router.post("/upload", protect, upload.single("file"), uploadFile);
router.get("/download/:id", protect, downloadFile);
router.get("/", protect, getFiles);
router.delete("/:id", protect, deleteFile);
router.post("/share", protect, shareFile);
router.post("/revoke", protect, revokeAccess);
router.get("/get-key/:id", protect, getFileKey);

module.exports = router;