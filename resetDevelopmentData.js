
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const fs = require("fs");
const path = require("path");
const readline = require("readline");

dotenv.config();

const User = require("./src/models/userModel");
const File = require("./src/models/fileModel");

const uploadsDir = path.resolve(__dirname, "uploads");

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

async function resetData() {
    try {
        if (process.env.NODE_ENV !== "development") {
            throw new Error(
                "Reset blocked. NODE_ENV must be development."
            );
        }

        if (!process.env.MONGO_URI) {
            throw new Error("MONGO_URI is missing.");
        }

        await mongoose.connect(process.env.MONGO_URI);

        const databaseName = mongoose.connection.name;

        console.log("\nConnected to database:", databaseName);
        console.log("WARNING: This operation is irreversible.");
        console.log("It will delete ALL users, file records and uploaded files.");

        rl.question(
            `\nType "${databaseName}" to confirm deletion: `,
            async (answer) => {
                if (answer.trim() !== databaseName) {
                    console.log("\nReset cancelled. No data deleted.");
                    rl.close();
                    await mongoose.disconnect();
                    return;
                }

                try {
                    const files = await File.find(
                        {},
                        { encryptedPath: 1 }
                    ).lean();

                    const userResult = await User.deleteMany({});
                    const fileResult = await File.deleteMany({});

                    // Only clean the explicitly configured uploads folder.
                    if (
                        path.basename(uploadsDir) !== "uploads" ||
                        !uploadsDir.startsWith(__dirname + path.sep)
                    ) {
                        throw new Error("Unsafe uploads directory path.");
                    }

                    if (fs.existsSync(uploadsDir)) {
                        const entries = await fs.promises.readdir(
                            uploadsDir,
                            { withFileTypes: true }
                        );

                        for (const entry of entries) {
                            await fs.promises.rm(
                                path.join(uploadsDir, entry.name),
                                { recursive: true, force: true }
                            );
                        }
                    }

                    console.log("\nRESET COMPLETED");
                    console.log("Users deleted:", userResult.deletedCount);
                    console.log("File records deleted:", fileResult.deletedCount);
                    console.log("Uploaded files cleaned:", true);
                    console.log("Previous file records found:", files.length);

                } catch (error) {
                    console.error("\nReset failed:", error.message);
                } finally {
                    rl.close();
                    await mongoose.disconnect();
                }
            }
        );

    } catch (error) {
        console.error("Could not perform reset:", error.message);
        rl.close();
        await mongoose.disconnect();
        process.exitCode = 1;
    }
}

resetData();
