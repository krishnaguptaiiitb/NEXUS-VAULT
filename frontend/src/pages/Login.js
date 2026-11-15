
import { useState } from "react";
import axios from "axios";
import {
  FaLock,
  FaShieldAlt,
  FaArrowRight
} from "react-icons/fa";
import "./Login.css";

const API_URL = "http://localhost:5000";

function Login({ setIsLoggedIn, setIsLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  // =====================================================
  // LOGIN
  // =====================================================

  const handleLogin = async (e) => {
    e.preventDefault();
    setErrorMessage("");

    if (!email.trim() || !password) {
      setErrorMessage("Please enter your email and password.");
      return;
    }

    try {
      setLoading(true);

      const res = await axios.post(
        `${API_URL}/api/users/login`,
        {
          email: email.trim().toLowerCase(),
          password
        }
      );

      const user = res.data;

      if (!user.token || !user._id) {
        throw new Error("Invalid login response from server.");
      }

      // =================================================
      // AUTHENTICATION DATA
      // =================================================

      localStorage.setItem("token", user.token);
      localStorage.setItem("userId", user._id);

      // =================================================
      // RSA PUBLIC KEY
      // =================================================

      if (user.publicKey) {
        localStorage.setItem("publicKey", user.publicKey);
      } else {
        localStorage.removeItem("publicKey");
      }

      // =================================================
      // X25519 PUBLIC KEY
      // =================================================

      if (user.x25519PublicKey) {
        localStorage.setItem(
          "x25519PublicKey",
          user.x25519PublicKey
        );
      } else {
        localStorage.removeItem("x25519PublicKey");
      }

      // =================================================
      // ML-KEM-768 PUBLIC KEY
      // =================================================

      if (user.mlkem768PublicKey) {
        localStorage.setItem(
          "mlkem768PublicKey",
          user.mlkem768PublicKey
        );
      } else {
        localStorage.removeItem("mlkem768PublicKey");
      }

      // =================================================
      // HYBRID KEY METADATA
      // =================================================

      const hybridKeyVersion = Number(
        user.hybridKeyVersion || 0
      );

      localStorage.setItem(
        "hybridKeyVersion",
        String(hybridKeyVersion)
      );

      if (user.hybridKeyCreatedAt) {
        localStorage.setItem(
          "hybridKeyCreatedAt",
          user.hybridKeyCreatedAt
        );
      } else {
        localStorage.removeItem("hybridKeyCreatedAt");
      }

      // =================================================
      // PRIVATE KEY AVAILABILITY
      // =================================================

      /*
        The server never returns private keys.

        Do not overwrite private keys during login.
        The dashboard will use the existing local keys
        or provide a backup recovery flow when necessary.
      */

      const hasRSAPrivateKey =
        Boolean(localStorage.getItem("privateKey"));

      const hasX25519PrivateKey =
        Boolean(localStorage.getItem("x25519PrivateKey"));

      const hasMLKEMPrivateKey =
        Boolean(localStorage.getItem("mlkem768PrivateKey"));

      const hasHybridPrivateKeys =
        hasX25519PrivateKey && hasMLKEMPrivateKey;

      localStorage.setItem(
        "hybridPrivateKeysAvailable",
        String(hasHybridPrivateKeys)
      );

      localStorage.setItem(
        "rsaPrivateKeyAvailable",
        String(hasRSAPrivateKey)
      );

      // =================================================
      // SUCCESS
      // =================================================

      setIsLoggedIn(true);

    } catch (error) {
      console.error("Login error:", error);

      setErrorMessage(
        error.response?.data?.message ||
        error.message ||
        "Unable to sign in. Please try again."
      );

    } finally {
      setLoading(false);
    }
  };

  // =====================================================
  // UI
  // =====================================================

  return (
    <main className="auth-page">
      <section className="auth-brand-panel">
        <div className="auth-brand">
          <div className="auth-brand-icon">
            <FaLock />
          </div>
          <span>Nexus Vault</span>
        </div>

        <div className="auth-brand-content">
          <span className="auth-eyebrow">
            <FaShieldAlt /> PRIVATE BY DESIGN
          </span>

          <h1>
            Your files.
            <br />
            Your keys.
            <br />
            <span>Your control.</span>
          </h1>

          <p>
            A secure space for your digital world. Encrypt your files,
            manage access, and keep control of your data.
          </p>
        </div>

        <div className="auth-brand-footer">
          <div className="auth-security-indicator">
            <span className="auth-status-dot"></span>
            Built around client-side encryption
          </div>
          <span>© 2026 Nexus Vault</span>
        </div>
      </section>

      <section className="auth-form-panel">
        <div className="auth-mobile-brand">
          <div className="auth-brand-icon">
            <FaLock />
          </div>
          <span>Nexus Vault</span>
        </div>

        <div className="auth-form-wrapper">
          <div className="auth-heading">
            <span className="auth-step-label">WELCOME BACK</span>
            <h2>Sign in to your vault</h2>
            <p>
              Enter your credentials to access your secure workspace.
            </p>
          </div>

          <form className="auth-form" onSubmit={handleLogin}>
            <div className="auth-field">
              <label htmlFor="login-email">Email address</label>
              <input
                id="login-email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                required
              />
            </div>

            <div className="auth-field">
              <div className="auth-label-row">
                <label htmlFor="login-password">Password</label>
              </div>

              <input
                id="login-password"
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </div>

            {errorMessage && (
              <div className="auth-error" role="alert">
                {errorMessage}
              </div>
            )}

            <button
              className="auth-submit"
              type="submit"
              disabled={loading}
            >
              {loading ? "Signing in..." : "Sign in to Nexus Vault"}
              {!loading && <FaArrowRight />}
            </button>
          </form>

          <div className="auth-switch">
            Don't have an account?
            <button
              type="button"
              onClick={() => setIsLogin(false)}
            >
              Create account
            </button>
          </div>

          <div className="auth-encryption-note">
            <FaShieldAlt />
            <span>
              Your encryption keys remain under your control.
            </span>
          </div>
        </div>

        <div className="auth-mobile-footer">
          © 2026 Nexus Vault
        </div>
      </section>
    </main>
  );
}

export default Login;
