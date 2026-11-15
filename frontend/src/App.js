
import { useState, useEffect } from "react";
import axios from "axios";

import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import socket from "./socket";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:5000";

function clearSession() {
    [
        "token",
        "userId",
        "publicKey",
        "privateKey",
        "x25519PublicKey",
        "mlkem768PublicKey",
        "x25519PrivateKey",
        "mlkem768PrivateKey",
        "hybridKeyVersion",
        "hybridKeyCreatedAt",
        "hybridPrivateKeysAvailable",
        "rsaPrivateKeyAvailable"
    ].forEach((key) => localStorage.removeItem(key));
}

function App() {
    const [isLoggedIn, setIsLoggedIn] = useState(
        Boolean(localStorage.getItem("token"))
    );

    const [isLogin, setIsLogin] = useState(true);

    const [checkingSession, setCheckingSession] = useState(
        Boolean(localStorage.getItem("token"))
    );

    useEffect(() => {
        const verifySession = async () => {
            const token = localStorage.getItem("token");

            if (!token) {
                setIsLoggedIn(false);
                setCheckingSession(false);
                return;
            }

            try {
                await axios.get(`${API_URL}/api/files`, {
                    headers: {
                        Authorization: `Bearer ${token}`
                    },
                    timeout: 10000
                });

                setIsLoggedIn(true);
            } catch (error) {
                if (
                    error.response?.status === 401 ||
                    error.response?.status === 403
                ) {
                    clearSession();
                    setIsLoggedIn(false);
                } else {
                    // Keep the session if the API is temporarily unavailable.
                    setIsLoggedIn(true);
                }
            } finally {
                setCheckingSession(false);
            }
        };

        verifySession();
    }, []);

    useEffect(() => {
        if (checkingSession) return;

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

    if (checkingSession) {
        return (
            <div className="app-loading">
                <div className="app-loading-spinner"></div>
                <p>Preparing your secure workspace...</p>
            </div>
        );
    }

    if (isLoggedIn) {
        return <Dashboard />;
    }

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
