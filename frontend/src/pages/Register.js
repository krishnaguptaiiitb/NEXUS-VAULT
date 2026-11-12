
import { useState } from "react";
import axios from "axios";
import {
  FaLock,
  FaShieldAlt,
  FaArrowRight,
  FaKey
} from "react-icons/fa";
import "./Register.css";

function Register({ setIsLogin }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  const generateKeys = async () => {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );

    const publicKey = await window.crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );

    const privateKey = await window.crypto.subtle.exportKey(
      "pkcs8",
      keyPair.privateKey
    );

    return {
      publicKey: btoa(
        String.fromCharCode(...new Uint8Array(publicKey))
      ),
      privateKey: btoa(
        String.fromCharCode(...new Uint8Array(privateKey))
      )
    };
  };

  const downloadPrivateKey = (privateKey) => {
    const blob = new Blob([privateKey], {
      type: "text/plain"
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "nexus-vault-private-key.txt";

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setErrorMessage("");

    if (!name.trim() || !email.trim() || !password) {
      setErrorMessage("Please fill in all fields.");
      return;
    }

    try {
      setLoading(true);

      const { publicKey, privateKey } = await generateKeys();

      await axios.post("http://localhost:5000/api/users/register", {
        name: name.trim(),
        email: email.trim(),
        password,
        publicKey
      });

      localStorage.setItem("privateKey", privateKey);

      downloadPrivateKey(privateKey);

      alert(
        "Account created successfully! Your private key has been downloaded. Store it somewhere safe."
      );

      setIsLogin(true);

    } catch (error) {
      console.error("Registration error:", error);

      setErrorMessage(
        error.response?.data?.message || "Registration failed. Please try again."
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
            <FaShieldAlt /> YOUR SPACE. YOUR RULES.
          </span>

          <h1>
            A safer home
            <br />
            for your
            <br />
            <span>digital life.</span>
          </h1>

          <p>
            Create your private workspace. Your files are encrypted
            in your browser, with keys designed to remain under your control.
          </p>
        </div>

        <div className="auth-brand-footer">
          <div className="auth-security-indicator">
            <span className="auth-status-dot"></span>
            Client-side encryption
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
            <span className="auth-step-label">GET STARTED</span>
            <h2>Create your account</h2>
            <p>
              Set up your secure workspace in just a few steps.
            </p>
          </div>

          <form className="auth-form" onSubmit={handleRegister}>
            <div className="auth-field">
              <label htmlFor="register-name">Full name</label>
              <input
                id="register-name"
                type="text"
                placeholder="Your name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoComplete="name"
                required
              />
            </div>

            <div className="auth-field">
              <label htmlFor="register-email">Email address</label>
              <input
                id="register-email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                required
              />
            </div>

            <div className="auth-field">
              <label htmlFor="register-password">Create password</label>
              <input
                id="register-password"
                type="password"
                placeholder="Choose a password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                required
              />
            </div>

            <div className="register-key-notice">
              <FaKey />
              <div>
                <strong>Your private key matters</strong>
                <p>
                  We'll generate a private key and download a backup
                  when your account is created. Keep it somewhere safe.
                </p>
              </div>
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
              {loading ? "Creating account..." : "Create secure account"}
              {!loading && <FaArrowRight />}
            </button>
          </form>

          <div className="auth-switch">
            Already have an account?
            <button type="button" onClick={() => setIsLogin(true)}>
              Sign in
            </button>
          </div>

          <div className="auth-encryption-note">
            <FaShieldAlt />
            <span>Your private key is not sent to our server.</span>
          </div>
        </div>

        <div className="auth-mobile-footer">
          © 2026 Nexus Vault
        </div>
      </section>
    </main>
  );
}

export default Register;
