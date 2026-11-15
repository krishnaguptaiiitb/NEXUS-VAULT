
import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import socket from "../socket";
import {
  wrapFileKeyForRecipient,
  unwrapFileKey
} from "../utils/hybridCrypto";
import {
  FaShieldAlt,
  FaFileAlt,
  FaFilePdf,
  FaFileImage,
  FaFileWord,
  FaFileExcel,
  FaFileArchive,
  FaFileCode,
  FaLock,
  FaDownload,
  FaCloudUploadAlt,
  FaShare,
  FaTrash,
  FaSearch,
  FaFolderOpen,
  FaUsers,
  FaSignOutAlt,
  FaKey,
  FaCheckCircle,
  FaPlus,
  FaTimes,
  FaBars,
  FaHome,
  FaSortAmountDown,
  FaCalendarAlt
} from "react-icons/fa";
import "./Dashboard.css";

const API_URL = "http://localhost:5000";
const CURRENT_ENCRYPTION_ALGORITHM = "AES-GCM";
const AES_KEY_LENGTH = 256;
const GCM_NONCE_LENGTH = 12;
const GCM_TAG_LENGTH = 128;

function getId(value) {
  if (!value) return "";
  return String(value._id || value);
}

function getFileDate(fileId) {
  try {
    if (!/^[a-fA-F0-9]{24}$/.test(fileId)) return null;
    return new Date(parseInt(fileId.substring(0, 8), 16) * 1000);
  } catch {
    return null;
  }
}

function formatDate(date) {
  if (!date || Number.isNaN(date.getTime())) return "Date unavailable";

  return date.toLocaleDateString("en-IN", {
    day: "numeric",
    month: "short",
    year: "numeric"
  });
}

function getFileType(filename = "") {
  const extension = filename.split(".").pop().toLowerCase();

  if (extension === "pdf") {
    return { label: "PDF document", Icon: FaFilePdf, className: "type-pdf" };
  }

  if (["png", "jpg", "jpeg", "gif", "webp", "svg", "bmp"].includes(extension)) {
    return { label: "Image", Icon: FaFileImage, className: "type-image" };
  }

  if (["doc", "docx", "txt", "rtf", "odt"].includes(extension)) {
    return { label: "Document", Icon: FaFileWord, className: "type-document" };
  }

  if (["xls", "xlsx", "csv"].includes(extension)) {
    return { label: "Spreadsheet", Icon: FaFileExcel, className: "type-spreadsheet" };
  }

  if (["zip", "rar", "7z", "tar", "gz"].includes(extension)) {
    return { label: "Archive", Icon: FaFileArchive, className: "type-archive" };
  }

  if (["js", "jsx", "ts", "tsx", "html", "css", "json", "py", "java", "cpp"].includes(extension)) {
    return { label: "Code file", Icon: FaFileCode, className: "type-code" };
  }

  return { label: "File", Icon: FaFileAlt, className: "type-default" };
}

function formatFileSize(bytes) {
  if (typeof bytes !== "number" || !Number.isFinite(bytes) || bytes < 0) {
    return null;
  }

  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function bufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.slice(i, i + chunkSize));
  }

  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function Dashboard() {
  const [file, setFile] = useState(null);
  const [files, setFiles] = useState([]);
  const [privateKeyFile, setPrivateKeyFile] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeView, setActiveView] = useState("all");
  const [sortBy, setSortBy] = useState("newest");
  const [uploading, setUploading] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [loadingFiles, setLoadingFiles] = useState(true);

  const token = localStorage.getItem("token");
  const currentUserId = localStorage.getItem("userId");

  // LOAD PRIVATE KEY MATERIAL
  const getPrivateKeyMaterial = async () => {
    let material = {};

    if (privateKeyFile) {
      const keyText = (await privateKeyFile.text()).trim();

      if (!keyText) {
        throw new Error("The selected private key file is empty.");
      }

      if (privateKeyFile.name.toLowerCase().endsWith(".json")) {
        let backup;

        try {
          backup = JSON.parse(keyText);
        } catch {
          throw new Error("Invalid hybrid private key backup JSON.");
        }

        material = {
          rsaPrivateKey: backup.rsaPrivateKey,
          x25519PrivateKey: backup.x25519PrivateKey,
          mlkem768PrivateKey: backup.mlkem768PrivateKey,
          keyVersion: backup.keyVersion
        };
      } else {
        material.rsaPrivateKey = keyText;
      }
    }

    material.rsaPrivateKey =
      material.rsaPrivateKey || localStorage.getItem("privateKey");
    material.x25519PrivateKey =
      material.x25519PrivateKey || localStorage.getItem("x25519PrivateKey");
    material.mlkem768PrivateKey =
      material.mlkem768PrivateKey || localStorage.getItem("mlkem768PrivateKey");

    return material;
  };

  const importRsaPrivateKey = async (privateKeyBase64) => {
    if (!privateKeyBase64) {
      throw new Error("RSA private key is unavailable. Select your RSA or hybrid backup.");
    }

    return window.crypto.subtle.importKey(
      "pkcs8",
      base64ToBytes(privateKeyBase64),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );
  };

  // FETCH FILES
  const fetchFiles = async () => {
    try {
      const res = await axios.get(`${API_URL}/api/files`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      setFiles(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      console.error("Fetch files error:", err);
      alert(err.response?.data?.message || "Unable to load your files.");
    } finally {
      setLoadingFiles(false);
    }
  };

  useEffect(() => {
    fetchFiles();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // REAL-TIME FILE SHARING AND ACCESS REVOCATION
  useEffect(() => {
    const handleAccessGranted = ({ message } = {}) => {
      fetchFiles();
      alert(message || "A new file has been shared with you.");
    };

    const handleAccessRevoked = ({ fileId, message } = {}) => {
      if (!fileId) return;

      setFiles((prevFiles) =>
        prevFiles.filter((f) => String(f._id) !== String(fileId))
      );

      alert(message || "Access to this file has been revoked.");
    };

    socket.on("file-access-granted", handleAccessGranted);
    socket.on("file-access-revoked", handleAccessRevoked);

    return () => {
      socket.off("file-access-granted", handleAccessGranted);
      socket.off("file-access-revoked", handleAccessRevoked);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // AES-256-GCM ENCRYPTION FOR NEW FILES
  const encryptFile = async (selectedFile) => {
    const buffer = await selectedFile.arrayBuffer();
    const startTime = performance.now();

    const key = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: AES_KEY_LENGTH },
      true,
      ["encrypt", "decrypt"]
    );

    // GCM requires a unique nonce for every encryption under the same key.
    // A fresh random 96-bit nonce is generated for each file.
    const nonce = window.crypto.getRandomValues(
      new Uint8Array(GCM_NONCE_LENGTH)
    );

    const encryptedData = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        tagLength: GCM_TAG_LENGTH
      },
      key,
      buffer
    );

    const endTime = performance.now();

    console.log(
      `[ENCRYPT-AES-GCM] Size: ${(selectedFile.size / 1000000).toFixed(2)} MB | Time: ${(endTime - startTime).toFixed(2)} ms`
    );

    const rawKey = await window.crypto.subtle.exportKey("raw", key);

    return {
      encryptedBlob: new Blob([encryptedData]),
      rawKey,
      iv: bufferToBase64(nonce),
      encryptionAlgorithm: CURRENT_ENCRYPTION_ALGORITHM
    };
  };

  // UPLOAD FILE WITH HYBRID KEY ENVELOPE
  const uploadFile = async () => {
    if (!file) {
      alert("Select a file first.");
      return;
    }

    try {
      setUploading(true);

      const {
        encryptedBlob,
        rawKey,
        iv,
        encryptionAlgorithm
      } = await encryptFile(file);

      const x25519PublicKey = localStorage.getItem("x25519PublicKey");
      const mlkem768PublicKey = localStorage.getItem("mlkem768PublicKey");

      if (!x25519PublicKey || !mlkem768PublicKey) {
        throw new Error(
          "Hybrid public keys are unavailable. Please sign in again or register hybrid keys."
        );
      }

      const envelope = await wrapFileKeyForRecipient(rawKey, {
        x25519PublicKey,
        mlkem768PublicKey
      });

      const formData = new FormData();
      formData.append("file", encryptedBlob, file.name);
      formData.append("iv", iv);
      formData.append("encryptionAlgorithm", encryptionAlgorithm);
      formData.append("envelopeVersion", String(envelope.envelopeVersion));
      formData.append("keyAlgorithm", envelope.keyAlgorithm);
      formData.append(
        "x25519EphemeralPublicKey",
        envelope.x25519EphemeralPublicKey
      );
      formData.append("mlkemCiphertext", envelope.mlkemCiphertext);
      formData.append("hkdfSalt", envelope.hkdfSalt);
      formData.append("wrappingNonce", envelope.wrappingNonce);
      formData.append("wrappedKey", envelope.wrappedKey);

      await axios.post(`${API_URL}/api/files/upload`, formData, {
        headers: { Authorization: `Bearer ${token}` }
      });

      alert(
        "File encrypted with AES-256-GCM and its key protected using X25519 + ML-KEM-768."
      );
      setFile(null);

      const input = document.getElementById("vault-file-input");
      if (input) input.value = "";

      await fetchFiles();
    } catch (err) {
      console.error("Hybrid upload error:", err);
      alert(err.response?.data?.message || err.message || "Upload failed.");
    } finally {
      setUploading(false);
    }
  };

  // DOWNLOAD AND DECRYPT
  // Supports legacy RSA envelopes and version-2 hybrid envelopes.
  // Supports AES-GCM and legacy AES-CBC file encryption.
  const downloadFile = async (id) => {
    try {
      const res = await axios.get(
        `${API_URL}/api/files/download/${id}`,
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );

      const {
        encryptedData,
        encryptedKey,
        iv,
        filename,
        encryptionAlgorithm,
        envelopeVersion,
        keyAlgorithm
      } = res.data;

      const algorithm = encryptionAlgorithm || "AES-CBC";

      if (!["AES-GCM", "AES-CBC"].includes(algorithm)) {
        throw new Error(`Unsupported encryption algorithm: ${algorithm}`);
      }

      const encryptedBuffer = base64ToBytes(encryptedData);
      const privateKeys = await getPrivateKeyMaterial();

      let decryptedKeyBuffer;

      if (
        Number(envelopeVersion) === 2 &&
        keyAlgorithm === "X25519-ML-KEM-768"
      ) {
        decryptedKeyBuffer = await unwrapFileKey(
          res.data,
          {
            x25519PrivateKey: privateKeys.x25519PrivateKey,
            mlkem768PrivateKey: privateKeys.mlkem768PrivateKey
          }
        );
      } else {
        if (!encryptedKey) {
          throw new Error("The file does not contain a supported key envelope.");
        }

        const privateKey = await importRsaPrivateKey(
          privateKeys.rsaPrivateKey
        );

        decryptedKeyBuffer = await window.crypto.subtle.decrypt(
          { name: "RSA-OAEP" },
          privateKey,
          base64ToBytes(encryptedKey)
        );
      }

      const aesKey = await window.crypto.subtle.importKey(
        "raw",
        decryptedKeyBuffer,
        { name: algorithm },
        false,
        ["decrypt"]
      );

      const startTime = performance.now();
      const nonce = base64ToBytes(iv);
      let decrypted;

      if (algorithm === "AES-GCM") {
        if (nonce.length !== GCM_NONCE_LENGTH) {
          throw new Error("Invalid AES-GCM nonce length.");
        }

        decrypted = await window.crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: nonce,
            tagLength: GCM_TAG_LENGTH
          },
          aesKey,
          encryptedBuffer
        );
      } else {
        if (nonce.length !== 16) {
          throw new Error("Invalid legacy AES-CBC IV length.");
        }

        decrypted = await window.crypto.subtle.decrypt(
          { name: "AES-CBC", iv: nonce },
          aesKey,
          encryptedBuffer
        );
      }

      const endTime = performance.now();

      console.log(
        `[DECRYPT-${algorithm}] File: ${filename} | Time: ${(endTime - startTime).toFixed(2)} ms`
      );

      const blob = new Blob([decrypted]);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");

      link.href = url;
      link.download = filename || "download";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
      console.error("Download/decryption error:", err);

      if (err.name === "OperationError") {
        alert(
          "Decryption failed. Your private key may be incorrect, or the encrypted data may have been modified."
        );
      } else {
        alert(err.message || "Decryption failed.");
      }
    }
  };

  // SHARE FILE USING A RECIPIENT-SPECIFIC ENVELOPE
  const shareFile = async (fileId) => {
    const email = window.prompt("Enter the email address to share with:");
    if (!email || !email.trim()) return;

    try {
      const userRes = await axios.post(
        `${API_URL}/api/users/get-by-email`,
        { email: email.trim().toLowerCase() },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      const receiver = userRes.data;

      if (!receiver?._id) {
        throw new Error("Recipient account was not found.");
      }

      const keyRes = await axios.get(
        `${API_URL}/api/files/get-key/${fileId}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );

      const ownerEnvelope = keyRes.data;
      const privateKeys = await getPrivateKeyMaterial();
      let rawFileKey;

      if (
        Number(ownerEnvelope.envelopeVersion) === 2 &&
        ownerEnvelope.keyAlgorithm === "X25519-ML-KEM-768"
      ) {
        rawFileKey = await unwrapFileKey(
          ownerEnvelope,
          {
            x25519PrivateKey: privateKeys.x25519PrivateKey,
            mlkem768PrivateKey: privateKeys.mlkem768PrivateKey
          }
        );
      } else {
        if (!ownerEnvelope.encryptedKey) {
          throw new Error("The owner's key envelope is invalid.");
        }

        const rsaPrivateKey = await importRsaPrivateKey(
          privateKeys.rsaPrivateKey
        );

        rawFileKey = await window.crypto.subtle.decrypt(
          { name: "RSA-OAEP" },
          rsaPrivateKey,
          base64ToBytes(ownerEnvelope.encryptedKey)
        );
      }

      let recipientEnvelope;

      if (
        receiver.x25519PublicKey &&
        receiver.mlkem768PublicKey
      ) {
        recipientEnvelope = await wrapFileKeyForRecipient(
          rawFileKey,
          {
            x25519PublicKey: receiver.x25519PublicKey,
            mlkem768PublicKey: receiver.mlkem768PublicKey
          }
        );
      } else if (receiver.publicKey) {
        const receiverPublicKey = await window.crypto.subtle.importKey(
          "spki",
          base64ToBytes(receiver.publicKey),
          { name: "RSA-OAEP", hash: "SHA-256" },
          false,
          ["encrypt"]
        );

        const encryptedKeyBuffer = await window.crypto.subtle.encrypt(
          { name: "RSA-OAEP" },
          receiverPublicKey,
          rawFileKey
        );

        recipientEnvelope = {
          encryptedKey: bufferToBase64(encryptedKeyBuffer)
        };
      } else {
        throw new Error(
          "The recipient has no supported public encryption keys."
        );
      }

      await axios.post(
        `${API_URL}/api/files/share`,
        {
          fileId,
          receiverId: receiver._id,
          ...recipientEnvelope
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      alert("File shared successfully.");
      await fetchFiles();
    } catch (error) {
      console.error("Share error:", error);
      alert(
        error.response?.data?.message ||
        error.message ||
        "Sharing failed."
      );
    }
  };

  // REVOKE ACCESS
  const revokeAccess = async (fileId, userId) => {
    if (!userId) {
      alert("Unable to identify this shared user.");
      return;
    }

    if (!window.confirm("Are you sure you want to revoke this user's access?")) {
      return;
    }

    try {
      const res = await axios.post(
        `${API_URL}/api/files/revoke`,
        { fileId, userId },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      alert(res.data.message || "Access revoked.");
      await fetchFiles();
    } catch (err) {
      console.error("Revoke error:", err);
      alert(err.response?.data?.message || "Revoke failed.");
    }
  };

  // DELETE FILE
  const deleteFile = async (id) => {
    if (!window.confirm("Are you sure you want to permanently delete this file?")) {
      return;
    }

    try {
      await axios.delete(`${API_URL}/api/files/${id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      alert("File deleted successfully.");
      setFiles((prev) => prev.filter((f) => f._id !== id));
    } catch (err) {
      console.error("Delete error:", err);
      alert(err.response?.data?.message || "Delete failed.");
    }
  };

  // LOGOUT
  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("userId");
    localStorage.removeItem("publicKey");
    localStorage.removeItem("privateKey");
    localStorage.removeItem("x25519PublicKey");
    localStorage.removeItem("mlkem768PublicKey");
    localStorage.removeItem("x25519PrivateKey");
    localStorage.removeItem("mlkem768PrivateKey");
    window.location.reload();
  };

  // FILE FILTERING
  const ownedFiles = useMemo(
    () => files.filter((f) => getId(f.owner) === currentUserId),
    [files, currentUserId]
  );

  const sharedFiles = useMemo(
    () => files.filter((f) => getId(f.owner) !== currentUserId),
    [files, currentUserId]
  );

  const displayedFiles = useMemo(() => {
    let result = files;

    if (activeView === "owned") result = ownedFiles;
    if (activeView === "shared") result = sharedFiles;

    if (searchQuery.trim()) {
      const query = searchQuery.trim().toLowerCase();

      result = result.filter((f) =>
        f.filename?.toLowerCase().includes(query)
      );
    }

    const sorted = [...result];

    sorted.sort((a, b) => {
      const nameA = (a.filename || "").toLowerCase();
      const nameB = (b.filename || "").toLowerCase();
      const dateA = getFileDate(a._id)?.getTime() || 0;
      const dateB = getFileDate(b._id)?.getTime() || 0;

      if (sortBy === "oldest") return dateA - dateB;
      if (sortBy === "name-asc") return nameA.localeCompare(nameB);
      if (sortBy === "name-desc") return nameB.localeCompare(nameA);

      return dateB - dateA;
    });

    return sorted;
  }, [files, ownedFiles, sharedFiles, activeView, searchQuery, sortBy]);

  const viewTitle =
    activeView === "shared"
      ? "Shared with me"
      : activeView === "owned"
        ? "My files"
        : "All files";

  const totalSharedRecipients = ownedFiles.reduce((total, f) => {
    const ownerId = getId(f.owner);

    const recipients = f.encryptedKeys?.filter(
      (k) => getId(k.user) !== ownerId
    ) || [];

    return total + recipients.length;
  }, 0);

  return (
    <div className="vault-app">
      {sidebarOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* SIDEBAR */}
      <aside className={`vault-sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <div className="brand-area">
          <div className="brand-icon">
            <FaShieldAlt />
          </div>

          <div>
            <h2>Nexus Vault</h2>
            <span>SECURE CLOUD STORAGE</span>
          </div>

          <button
            className="mobile-close"
            onClick={() => setSidebarOpen(false)}
            aria-label="Close menu"
          >
            <FaTimes />
          </button>
        </div>

        <div className="sidebar-section">
          <span className="sidebar-label">WORKSPACE</span>

          <button
            className={`nav-item ${activeView === "all" ? "active" : ""}`}
            onClick={() => {
              setActiveView("all");
              setSidebarOpen(false);
            }}
          >
            <FaHome />
            <span>Overview</span>
          </button>

          <button
            className={`nav-item ${activeView === "owned" ? "active" : ""}`}
            onClick={() => {
              setActiveView("owned");
              setSidebarOpen(false);
            }}
          >
            <FaFolderOpen />
            <span>My files</span>
            <span className="nav-count">{ownedFiles.length}</span>
          </button>

          <button
            className={`nav-item ${activeView === "shared" ? "active" : ""}`}
            onClick={() => {
              setActiveView("shared");
              setSidebarOpen(false);
            }}
          >
            <FaUsers />
            <span>Shared with me</span>
            <span className="nav-count">{sharedFiles.length}</span>
          </button>
        </div>

        <div className="sidebar-security">
          <div className="security-icon">
            <FaLock />
          </div>

          <div>
            <strong>Your files are encrypted</strong>
            <p>Encryption happens before upload.</p>
          </div>
        </div>

        <div className="sidebar-bottom">
          <div className="sidebar-user">
            <div className="user-avatar">
              <FaShieldAlt />
            </div>

            <div className="user-details">
              <strong>My Account</strong>
              <span>Personal workspace</span>
            </div>
          </div>

          <button className="logout-button" onClick={logout}>
            <FaSignOutAlt />
            <span>Disconnect</span>
          </button>
        </div>
      </aside>

      {/* MAIN WORKSPACE */}
      <main className="vault-main">
        <header className="vault-topbar">
          <div className="topbar-left">
            <button
              className="mobile-menu"
              onClick={() => setSidebarOpen(true)}
              aria-label="Open menu"
            >
              <FaBars />
            </button>

            <div className="breadcrumb">
              <span>Workspace</span>
              <span className="breadcrumb-separator">/</span>
              <strong>{viewTitle}</strong>
            </div>
          </div>

          <div className="topbar-right">
            <div className="connection-status">
              <span className="status-dot" />
              Private workspace
            </div>

            <div className="topbar-avatar">
              <FaShieldAlt />
            </div>
          </div>
        </header>

        <div className="vault-content">
          {/* PAGE INTRO */}
          <section className="page-heading">
            <div>
              <span className="eyebrow">YOUR DIGITAL SPACE</span>
              <h1>{viewTitle}</h1>
              <p>
                Manage your encrypted files and keep your digital assets
                protected.
              </p>
            </div>

            <button
              className="primary-button"
              onClick={() =>
                document
                  .getElementById("upload-section")
                  ?.scrollIntoView({ behavior: "smooth" })
              }
            >
              <FaPlus />
              Upload a file
            </button>
          </section>

          {/* STATS */}
          <section className="overview-grid">
            <div className="overview-card">
              <div className="overview-card-top">
                <div className="overview-icon teal-icon">
                  <FaFolderOpen />
                </div>
                <span className="overview-caption">YOUR STORAGE</span>
              </div>

              <h2>{files.length}</h2>
              <p>Total encrypted files</p>
            </div>

            <div className="overview-card">
              <div className="overview-card-top">
                <div className="overview-icon lavender-icon">
                  <FaLock />
                </div>
                <span className="overview-caption">ENCRYPTION</span>
              </div>

              <h2>AES-256</h2>
              <p>Client-side file encryption</p>
            </div>

            <div className="overview-card">
              <div className="overview-card-top">
                <div className="overview-icon peach-icon">
                  <FaUsers />
                </div>
                <span className="overview-caption">SHARING</span>
              </div>

              <h2>{totalSharedRecipients}</h2>
              <p>File sharing recipients</p>
            </div>
          </section>

          {/* PRIVATE KEY */}
          <section className="security-panel">
            <div className="security-panel-icon">
              <FaKey />
            </div>

            <div className="security-panel-content">
              <div className="security-title-row">
                <h3>Private key configuration</h3>

                {privateKeyFile && (
                  <span className="key-ready">
                    <FaCheckCircle /> Key loaded
                  </span>
                )}
              </div>

              <p>
                Select your RSA private key backup (.txt) or hybrid private
                key backup (.json) to decrypt downloads and share files. Your
                private keys stay on this device while you use the application.
              </p>

              <label className="key-upload-button">
                <FaKey />
                {privateKeyFile ? "Change private key" : "Choose private key"}

                <input
                  type="file"
                  accept=".txt,.json,application/json,text/plain"
                  onChange={(e) =>
                    setPrivateKeyFile(e.target.files?.[0] || null)
                  }
                />
              </label>

              {privateKeyFile && (
                <span className="selected-key-name">
                  {privateKeyFile.name}
                </span>
              )}
            </div>
          </section>

          {/* UPLOAD SECTION */}
          <section className="upload-panel" id="upload-section">
            <div className="section-heading">
              <div>
                <span className="eyebrow">ADD TO YOUR VAULT</span>
                <h2>Upload new file</h2>
                <p>Your file is encrypted in your browser before uploading.</p>
              </div>
            </div>

            <div className={`upload-dropzone ${file ? "has-file" : ""}`}>
              <div className="upload-cloud-icon">
                <FaCloudUploadAlt />
              </div>

              <div className="upload-copy">
                <h3>{file ? file.name : "Choose a file to get started"}</h3>

                <p>
                  {file
                    ? `${formatFileSize(file.size)} selected`
                    : "Select a file from your device to encrypt and store it securely."}
                </p>
              </div>

              <div className="upload-actions">
                <label className="browse-button">
                  Browse files
                  <input
                    id="vault-file-input"
                    type="file"
                    onChange={(e) => setFile(e.target.files?.[0] || null)}
                  />
                </label>

                <button
                  className="primary-button upload-submit"
                  onClick={uploadFile}
                  disabled={!file || uploading}
                >
                  <FaCloudUploadAlt />
                  {uploading ? "Encrypting & uploading..." : "Upload securely"}
                </button>
              </div>
            </div>
          </section>

          {/* FILE COLLECTION */}
          <section className="files-section">
            <div className="files-heading">
              <div>
                <span className="eyebrow">YOUR COLLECTION</span>
                <h2>{viewTitle}</h2>
                <p>
                  {displayedFiles.length}{" "}
                  {displayedFiles.length === 1 ? "file" : "files"} available
                </p>
              </div>

              <div className="file-toolbar">
                <div className="search-box">
                  <FaSearch />

                  <input
                    type="text"
                    placeholder="Search files..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />

                  {searchQuery && (
                    <button
                      onClick={() => setSearchQuery("")}
                      aria-label="Clear search"
                    >
                      <FaTimes />
                    </button>
                  )}
                </div>

                <div className="sort-box">
                  <FaSortAmountDown />

                  <select
                    value={sortBy}
                    onChange={(e) => setSortBy(e.target.value)}
                    aria-label="Sort files"
                  >
                    <option value="newest">Newest first</option>
                    <option value="oldest">Oldest first</option>
                    <option value="name-asc">Name A-Z</option>
                    <option value="name-desc">Name Z-A</option>
                  </select>
                </div>
              </div>
            </div>

            {loadingFiles ? (
              <div className="empty-state">
                <div className="loading-spinner" />
                <h3>Loading your files</h3>
                <p>Preparing your secure collection...</p>
              </div>
            ) : displayedFiles.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">
                  <FaFolderOpen />
                </div>

                <h3>
                  {searchQuery
                    ? "No matching files found"
                    : activeView === "shared"
                      ? "Nothing shared with you yet"
                      : "Your vault is waiting"}
                </h3>

                <p>
                  {searchQuery
                    ? "Try searching with a different file name."
                    : activeView === "shared"
                      ? "Files shared with your account will appear here."
                      : "Upload your first file to start building your secure collection."}
                </p>

                {!searchQuery && activeView !== "shared" && (
                  <button
                    className="primary-button"
                    onClick={() =>
                      document
                        .getElementById("upload-section")
                        ?.scrollIntoView({ behavior: "smooth" })
                    }
                  >
                    <FaPlus />
                    Upload your first file
                  </button>
                )}
              </div>
            ) : (
              <div className="vault-file-grid">
                {displayedFiles.map((f) => {
                  const ownerId = getId(f.owner);
                  const isOwner = currentUserId === ownerId;

                  const sharedUsers =
                    f.encryptedKeys?.filter(
                      (k) => getId(k.user) !== ownerId
                    ) || [];

                  const fileType = getFileType(f.filename);
                  const FileIcon = fileType.Icon;
                  const fileDate = getFileDate(f._id);

                  const fileSize = formatFileSize(
                    f.originalSize ?? f.size
                  );

                  return (
                    <article className="vault-file-card" key={f._id}>
                      <div className="file-card-top">
                        <div className={`file-type-icon ${fileType.className}`}>
                          <FileIcon />
                        </div>

                        <span className="encrypted-tag">
                          <FaLock />
                          Encrypted
                        </span>
                      </div>

                      <div className="file-card-info">
                        <h3 title={f.filename}>{f.filename}</h3>

                        <span className="file-type-label">
                          {fileType.label}
                        </span>
                      </div>

                      <div className="file-metadata">
                        <div>
                          <FaCalendarAlt />
                          <span>
                            {fileDate
                              ? `Added ${formatDate(fileDate)}`
                              : "Upload date unavailable"}
                          </span>
                        </div>

                        <div>
                          <FaShieldAlt />
                          <span>
                            {isOwner ? "Owned by you" : "Shared with you"}
                          </span>
                        </div>

                        {fileSize && (
                          <div>
                            <FaFileAlt />
                            <span>{fileSize}</span>
                          </div>
                        )}
                      </div>

                      <div className="file-card-divider" />

                      <div className="file-card-actions">
                        <button
                          className="file-action-button download-action"
                          onClick={() => downloadFile(f._id)}
                          title="Download and decrypt"
                        >
                          <FaDownload />
                          <span>Decrypt</span>
                        </button>

                        {isOwner && (
                          <>
                            <button
                              className="file-action-button"
                              onClick={() => shareFile(f._id)}
                              title="Share file"
                            >
                              <FaShare />
                              <span>Share</span>
                            </button>

                            <button
                              className="file-action-button delete-action"
                              onClick={() => deleteFile(f._id)}
                              title="Delete file"
                            >
                              <FaTrash />
                              <span>Delete</span>
                            </button>
                          </>
                        )}
                      </div>

                      {isOwner && sharedUsers.length > 0 && (
                        <div className="shared-users">
                          <div className="shared-users-heading">
                            <FaUsers />
                            <span>Shared with</span>
                            <span className="shared-count">
                              {sharedUsers.length}
                            </span>
                          </div>

                          {sharedUsers.map((k, index) => {
                            const userId = getId(k.user);
                            const email =
                              typeof k.user === "object"
                                ? k.user.email
                                : "Shared user";

                            return (
                              <div
                                className="shared-user-row"
                                key={userId || index}
                              >
                                <span className="shared-user-email">
                                  {email || "Shared user"}
                                </span>

                                <button
                                  onClick={() =>
                                    revokeAccess(f._id, userId)
                                  }
                                  title="Revoke access"
                                >
                                  Revoke
                                </button>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </article>
                  );
                })}
              </div>
            )}
          </section>

          <footer className="vault-footer">
            <div>
              <FaShieldAlt />
              <span>Nexus Vault</span>
            </div>

            <p>Secure storage. Private by design.</p>
          </footer>
        </div>
      </main>
    </div>
  );
}

export default Dashboard;
