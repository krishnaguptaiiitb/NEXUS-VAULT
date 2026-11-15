
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

const allowedOrigins = (process.env.CLIENT_URL || "http://localhost:3000")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);

const corsOptions = {
    origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        return callback(new Error("Origin not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
};

const io = new Server(server, {
    cors: corsOptions
});

app.set("io", io);

app.use(cors(corsOptions));
app.use(express.json({ limit: "1mb" }));

app.get("/", (req, res) => {
    res.status(200).json({
        message: "Nexus Vault API is running",
        status: "ok"
    });
});

app.use("/api/users", userRoutes);
app.use("/api/files", fileRoutes);

io.use((socket, next) => {
    try {
        const token = socket.handshake.auth?.token;

        if (!token) {
            return next(new Error("Authentication required"));
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        socket.userId = decoded.id;
        return next();
    } catch {
        return next(new Error("Invalid or expired token"));
    }
});

io.on("connection", (socket) => {
    socket.join(`user:${socket.userId}`);

    console.log(`Authenticated user connected: ${socket.userId}`);

    socket.on("disconnect", () => {
        console.log(`User disconnected: ${socket.userId}`);
    });
});

// Central error handler, including Multer upload errors.
app.use((error, req, res, next) => {
    if (res.headersSent) {
        return next(error);
    }

    if (error.name === "MulterError") {
        const message = error.code === "LIMIT_FILE_SIZE"
            ? "File exceeds the maximum upload size."
            : error.message;

        return res.status(400).json({ message });
    }

    if (error.message === "Origin not allowed by CORS") {
        return res.status(403).json({ message: error.message });
    }

    console.error("Unhandled server error:", error.message);

    return res.status(500).json({
        message: "An unexpected server error occurred."
    });
});

const PORT = process.env.PORT || 5000;

async function startServer() {
    if (!process.env.MONGO_URI) {
        throw new Error("MONGO_URI is not configured.");
    }

    if (!process.env.JWT_SECRET) {
        throw new Error("JWT_SECRET is not configured.");
    }

    await connectDB();

    server.listen(PORT, () => {
        console.log(`Nexus Vault API running on port ${PORT}`);
        console.log("Authenticated Socket.IO server is ready.");
    });
}

startServer().catch((error) => {
    console.error("Server startup failed:", error.message);
    process.exit(1);
});
