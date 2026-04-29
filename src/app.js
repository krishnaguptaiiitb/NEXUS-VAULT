const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const connectDB = require("./config/db");
const userRoutes = require("./routes/userRoutes");
const fileRoutes = require("./routes/fileRoutes");

dotenv.config();

const app = express();

connectDB();

app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
    res.status(200).send("Server is running successfully 🚀");
});

app.use("/api/users", userRoutes);
app.use("/api/files", fileRoutes);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});