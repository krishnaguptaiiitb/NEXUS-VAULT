
const express = require("express");

const {
    registerUser,
    loginUser,
    getUserByEmail,
    updateHybridPublicKeys
} = require("../controllers/userController");

const protect = require("../middleware/authMiddleware");

const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);

router.post("/get-by-email", protect, getUserByEmail);

// Register or update the logged-in user's hybrid public keys.
router.put("/register-hybrid-keys", protect, updateHybridPublicKeys);

module.exports = router;
