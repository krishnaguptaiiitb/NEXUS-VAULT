
const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const http = require("http");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");

const connectDB = require("./config/db");
const userRoutes = require("./routes/userRoutes");
const fileRoutes = require("./routes/fileRoutes");

dotenv.config();

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: process.env.CLIENT_URL || "*",
        methods: ["GET", "POST"]
    }
});

// Make Socket.IO available to controllers
app.set("io", io);

// Database connection
connectDB();

// Middleware
app.use(express.json());
app.use(cors());

// Health check
app.get("/", (req, res) => {
    res.status(200).send("Server is running successfully 🚀");
});

// API routes
app.use("/api/users", userRoutes);
app.use("/api/files", fileRoutes);

// Authenticate Socket.IO connections
io.use((socket, next) => {
    try {
        const token = socket.handshake.auth.token;

        if (!token) {
            return next(new Error("Authentication required"));
        }

        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        socket.userId = decoded.id;

        next();

    } catch (error) {
        next(new Error("Invalid or expired token"));
    }
});

// Handle authenticated connections
io.on("connection", (socket) => {
    const userRoom = `user:${socket.userId}`;

    socket.join(userRoom);

    console.log(
        `Authenticated user connected: ${socket.userId}`
    );

    socket.on("disconnect", () => {
        console.log(
            `User disconnected: ${socket.userId}`
        );
    });
});

// Start server
const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log("Authenticated Socket.IO server is ready 🚀");
});
