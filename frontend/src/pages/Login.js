
import { useState } from "react";
import axios from "axios";
import { FaLock, FaShieldAlt, FaArrowRight } from "react-icons/fa";
import "./Login.css";

function Login({ setIsLoggedIn, setIsLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  const handleLogin = async (e) => {
    e.preventDefault();
    setErrorMessage("");

    if (!email.trim() || !password) {
      setErrorMessage("Please enter your email and password.");
      return;
    }

    try {
      setLoading(true);

      const res = await axios.post("http://localhost:5000/api/users/login", {
        email,
        password,
      });

      localStorage.setItem("token", res.data.token);
      localStorage.setItem("userId", res.data._id);
      localStorage.setItem("publicKey", res.data.publicKey);

      setIsLoggedIn(true);
    } catch (error) {
      setErrorMessage(
        error.response?.data?.message || "Unable to sign in. Please try again."
      );
    } finally {
      setLoading(false);
    }
  };

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
            <p>Enter your credentials to access your secure workspace.</p>
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
            <button type="button" onClick={() => setIsLogin(false)}>
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
