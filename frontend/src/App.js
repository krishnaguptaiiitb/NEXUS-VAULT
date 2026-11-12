
import { useState, useEffect } from "react";
import axios from "axios";

import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import socket from "./socket";

function App() {
    const [isLoggedIn, setIsLoggedIn] = useState(
        !!localStorage.getItem("token")
    );

    const [isLogin, setIsLogin] = useState(true);

    const [checkingSession, setCheckingSession] = useState(
        !!localStorage.getItem("token")
    );

    // Verify existing login session
    useEffect(() => {
        const verifySession = async () => {
            const token = localStorage.getItem("token");

            if (!token) {
                setIsLoggedIn(false);
                setCheckingSession(false);
                return;
            }

            try {
                await axios.get("http://localhost:5000/api/files", {
                    headers: {
                        Authorization: `Bearer ${token}`
                    }
                });

                setIsLoggedIn(true);

            } catch (error) {
                if (
                    error.response?.status === 401 ||
                    error.response?.status === 403
                ) {
                    localStorage.removeItem("token");
                    localStorage.removeItem("userId");
                    localStorage.removeItem("publicKey");

                    setIsLoggedIn(false);

                } else {
                    // Preserve session if server is temporarily unavailable
                    setIsLoggedIn(true);
                }

            } finally {
                setCheckingSession(false);
            }
        };

        verifySession();
    }, []);

    // Connect authenticated user to Socket.IO
    useEffect(() => {
        if (checkingSession) {
            return;
        }

        if (!isLoggedIn) {
            socket.disconnect();
            return;
        }

        const token = localStorage.getItem("token");

        if (!token) {
            socket.disconnect();
            return;
        }

        socket.auth = { token };
        socket.connect();

        return () => {
            socket.disconnect();
        };
    }, [isLoggedIn, checkingSession]);

    // Loading screen
    if (checkingSession) {
        return (
            <div className="app-loading">
                <div className="app-loading-spinner"></div>
                <p>Preparing your secure workspace...</p>
            </div>
        );
    }

    // Dashboard
    if (isLoggedIn) {
        return <Dashboard />;
    }

    // Login / Register
    return isLogin ? (
        <Login
            setIsLoggedIn={setIsLoggedIn}
            setIsLogin={setIsLogin}
        />
    ) : (
        <Register setIsLogin={setIsLogin} />
    );
}

export default App;
