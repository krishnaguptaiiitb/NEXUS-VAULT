const express = require("express");
const { registerUser, loginUser, getUserByEmail } = require("../controllers/userController");
const protect = require("../middleware/authMiddleware"); // ✅ ADD THIS

const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/get-by-email", protect, getUserByEmail);

module.exports = router;