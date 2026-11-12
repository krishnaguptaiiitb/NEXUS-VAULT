
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const generateToken = (id) => {
    if (!process.env.JWT_SECRET) {
        throw new Error("JWT_SECRET is not configured");
    }

    return jwt.sign(
        { id },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
    );
};

const registerUser = async (req, res) => {
    try {
        const { name, email, password, publicKey } = req.body;

        const userExists = await User.findOne({ email });

        if (userExists) {
            return res.status(400).json({
                message: "User already exists"
            });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const user = await User.create({
            name,
            email,
            password: hashedPassword,
            publicKey
        });

        res.status(201).json({
            _id: user._id,
            email: user.email,
            token: generateToken(user._id)
        });

    } catch (error) {
        console.error("Registration error:", error.message);
        res.status(500).json({ message: "Server error" });
    }
};

const getUserByEmail = async (req, res) => {
    try {
        const email = req.body.email.trim().toLowerCase();

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        res.json({
            _id: user._id,
            email: user.email,
            publicKey: user.publicKey
        });

    } catch (error) {
        res.status(500).json({
            message: "Error fetching user"
        });
    }
};

const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({
                message: "Invalid credentials"
            });
        }

        const isMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!isMatch) {
            return res.status(400).json({
                message: "Invalid credentials"
            });
        }

        res.status(200).json({
            _id: user._id,
            email: user.email,
            token: generateToken(user._id),
            publicKey: user.publicKey
        });

    } catch (error) {
        console.error("Login error:", error.message);
        res.status(500).json({ message: "Server error" });
    }
};

module.exports = {
    registerUser,
    loginUser,
    getUserByEmail
};
