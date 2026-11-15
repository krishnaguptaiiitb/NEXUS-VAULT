
import { useState } from "react";
import axios from "axios";
import {
  FaLock,
  FaShieldAlt,
  FaArrowRight,
  FaKey
} from "react-icons/fa";
import "./Register.css";

const API_URL = "http://localhost:5000";

const toBase64 = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(
      ...bytes.subarray(i, i + 0x8000)
    );
  }

  return btoa(binary);
};

const downloadTextFile = (
  content,
  filename,
  type = "text/plain"
) => {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  setTimeout(() => URL.revokeObjectURL(url), 1000);
};

function Register({ setIsLogin }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  // =====================================================
  // CHECK BROWSER CRYPTOGRAPHY SUPPORT
  // =====================================================

  const checkCryptoSupport = () => {
    if (!window.isSecureContext || !window.crypto?.subtle) {
      throw new Error(
        "Secure browser cryptography is unavailable. Use HTTPS or localhost."
      );
    }

    if (
      typeof window.crypto.subtle.encapsulateBits !== "function" ||
      typeof window.crypto.subtle.decapsulateBits !== "function"
    ) {
      throw new Error(
        "Your browser does not support the required ML-KEM-768 WebCrypto APIs. Please use a compatible browser."
      );
    }
  };

  // =====================================================
  // GENERATE CRYPTOGRAPHIC KEYS
  // =====================================================

  const generateKeys = async () => {
    checkCryptoSupport();

    // Legacy RSA-OAEP-2048 key pair.
    const rsaKeyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );

    const rsaPublicKey = await window.crypto.subtle.exportKey(
      "spki",
      rsaKeyPair.publicKey
    );

    const rsaPrivateKey = await window.crypto.subtle.exportKey(
      "pkcs8",
      rsaKeyPair.privateKey
    );

    // X25519 key agreement.
    const x25519KeyPair = await window.crypto.subtle.generateKey(
      {
        name: "X25519"
      },
      true,
      ["deriveBits"]
    );

    const x25519PublicKey = await window.crypto.subtle.exportKey(
      "raw",
      x25519KeyPair.publicKey
    );

    const x25519PrivateKey = await window.crypto.subtle.exportKey(
      "pkcs8",
      x25519KeyPair.privateKey
    );

    // Post-quantum ML-KEM-768.
    const mlkemKeyPair = await window.crypto.subtle.generateKey(
      {
        name: "ML-KEM-768"
      },
      true,
      ["encapsulateBits", "decapsulateBits"]
    );

    const mlkemPublicKey = await window.crypto.subtle.exportKey(
      "raw-public",
      mlkemKeyPair.publicKey
    );

    const mlkemPrivateKey = await window.crypto.subtle.exportKey(
      "raw-seed",
      mlkemKeyPair.privateKey
    );

    // Validate exported key lengths.
    if (new Uint8Array(rsaPublicKey).length === 0) {
      throw new Error("RSA public-key generation failed.");
    }

    if (new Uint8Array(x25519PublicKey).length !== 32) {
      throw new Error("Invalid X25519 public-key length.");
    }

    if (new Uint8Array(mlkemPublicKey).length !== 1184) {
      throw new Error("Invalid ML-KEM-768 public-key length.");
    }

    if (new Uint8Array(mlkemPrivateKey).length !== 64) {
      throw new Error("Invalid ML-KEM-768 private-key length.");
    }

    return {
      publicKeys: {
        publicKey: toBase64(rsaPublicKey),
        x25519PublicKey: toBase64(x25519PublicKey),
        mlkem768PublicKey: toBase64(mlkemPublicKey)
      },

      privateKeys: {
        product: "Nexus Vault",
        backupType: "Hybrid Private Key Backup",
        backupVersion: 1,
        warning:
          "Contains private cryptographic keys. Anyone with this file may be able to access files encrypted for this account. Keep it secure.",

        rsaPrivateKey: toBase64(rsaPrivateKey),
        x25519PrivateKey: toBase64(x25519PrivateKey),
        mlkem768PrivateKey: toBase64(mlkemPrivateKey),

        keyVersion: 1,

        algorithms: {
          rsa: "RSA-OAEP-2048",
          x25519: "X25519",
          postQuantum: "ML-KEM-768"
        }
      }
    };
  };

  // =====================================================
  // SAVE PRIVATE KEY BACKUPS
  // =====================================================

  const savePrivateKeyBackups = (privateKeys) => {
    // Legacy RSA-only backup.
    downloadTextFile(
      privateKeys.rsaPrivateKey,
      "nexus-vault-private-key.txt"
    );

    // Complete hybrid private-key backup.
    downloadTextFile(
      JSON.stringify(privateKeys, null, 2),
      "nexus-vault-hybrid-private-keys.json",
      "application/json"
    );
  };

  // =====================================================
  // STORE ACCOUNT AND PRIVATE KEY INFORMATION
  // =====================================================

  const storeAccountData = (responseData, publicKeys, privateKeys) => {
    localStorage.setItem("token", responseData.token);
    localStorage.setItem("userId", responseData._id);

    // Legacy RSA compatibility.
    localStorage.setItem(
      "privateKey",
      privateKeys.rsaPrivateKey
    );

    localStorage.setItem(
      "publicKey",
      publicKeys.publicKey
    );

    // Hybrid private keys.
    localStorage.setItem(
      "x25519PrivateKey",
      privateKeys.x25519PrivateKey
    );

    localStorage.setItem(
      "mlkem768PrivateKey",
      privateKeys.mlkem768PrivateKey
    );

    // Hybrid public keys.
    localStorage.setItem(
      "x25519PublicKey",
      publicKeys.x25519PublicKey
    );

    localStorage.setItem(
      "mlkem768PublicKey",
      publicKeys.mlkem768PublicKey
    );

    localStorage.setItem(
      "hybridKeyVersion",
      String(responseData.hybridKeyVersion || 1)
    );
  };

  // =====================================================
  // REGISTRATION
  // =====================================================

  const handleRegister = async (e) => {
    e.preventDefault();
    setErrorMessage("");

    if (!name.trim() || !email.trim() || !password) {
      setErrorMessage("Please fill in all fields.");
      return;
    }

    if (password.length < 8 || password.length > 128) {
      setErrorMessage(
        "Password must be between 8 and 128 characters."
      );
      return;
    }

    try {
      setLoading(true);

      // Step 1: Generate all cryptographic keys.
      const { publicKeys, privateKeys } = await generateKeys();

      // Step 2: Generate backups before contacting the server.
      // This protects against a lost registration response.
      savePrivateKeyBackups(privateKeys);

      // Step 3: Register account and all public keys together.
      const response = await axios.post(
        `${API_URL}/api/users/register`,
        {
          name: name.trim(),
          email: email.trim().toLowerCase(),
          password,

          publicKey: publicKeys.publicKey,
          x25519PublicKey: publicKeys.x25519PublicKey,
          mlkem768PublicKey: publicKeys.mlkem768PublicKey
        },
        {
          timeout: 30000
        }
      );

      if (!response.data?._id || !response.data?.token) {
        throw new Error(
          "The server response was incomplete. Your private-key backups have been generated. Please check whether the account was created before trying again."
        );
      }

      // Step 4: Store account and key information after success.
      storeAccountData(
        response.data,
        publicKeys,
        privateKeys
      );

      alert(
        "Account created successfully. Both private-key backups have been generated. Store them securely."
      );

      setIsLogin(true);

    } catch (error) {
      console.error("Registration error:", error);

      const message =
        error.response?.data?.message ||
        error.message ||
        "Registration failed. Please try again.";

      setErrorMessage(message);

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
                minLength={8}
                maxLength={128}
                required
              />
            </div>

            <div className="register-key-notice">
              <FaKey />
              <div>
                <strong>Your private keys matter</strong>
                <p>
                  RSA, X25519 and ML-KEM-768 keys are generated
                  in your browser. Their private portions are
                  never sent to the server. Two backup files
                  will be generated. Store them securely.
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
            <button
              type="button"
              onClick={() => setIsLogin(true)}
            >
              Sign in
            </button>
          </div>

          <div className="auth-encryption-note">
            <FaShieldAlt />
            <span>Your private keys are not sent to our server.</span>
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
