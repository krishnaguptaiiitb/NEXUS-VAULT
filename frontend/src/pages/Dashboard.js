import { useEffect, useState } from "react";
import axios from "axios";
import {
  FaFileAlt,
  FaLock,
  FaDownload,
  FaCloudUploadAlt,
  FaShieldAlt,
  FaShare,
  FaTrash
} from "react-icons/fa";

function Dashboard() {
  const [file, setFile] = useState(null);
  const [files, setFiles] = useState([]);
  const [privateKeyFile, setPrivateKeyFile] = useState(null);

  const token = localStorage.getItem("token");
  const currentUserId = localStorage.getItem("userId");

  // 🔐 SAFE BASE64 CONVERSION
  const bufferToBase64 = (buffer) => {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    const chunkSize = 0x8000;

    for (let i = 0; i < bytes.length; i += chunkSize) {
      binary += String.fromCharCode(...bytes.slice(i, i + chunkSize));
    }

    return btoa(binary);
  };

  // 🔐 GET PRIVATE KEY FROM FILE
  const getPrivateKey = async () => {
    if (!privateKeyFile) {
      throw new Error("Upload private key first");
    }

    const keyText = await privateKeyFile.text();

    return await window.crypto.subtle.importKey(
      "pkcs8",
      Uint8Array.from(atob(keyText), c => c.charCodeAt(0)),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );
  };

  // 🗑️ DELETE FILE
  const deleteFile = async (id) => {
    if (!window.confirm("Are you sure you want to permanently delete this file?")) return;

    try {
      await axios.delete(`http://localhost:5000/api/files/${id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      alert("File deleted successfully 🗑️");
      
      // 🔥 instant UI update (removes the file from the screen without reloading)
      setFiles(prev => prev.filter(f => f._id !== id));

    } catch (err) {
      console.error(err);
      alert(err.response?.data?.message || "Delete failed");
    }
  };
  // 🔐 ENCRYPT FILE (AES)
// 🔐 ENCRYPT FILE (AES)
  const encryptFile = async (file) => {
    const buffer = await file.arrayBuffer();

    // 👉 1. ADD THIS LINE STARTING THE TIMER
    const startTime = performance.now(); 

    const key = await window.crypto.subtle.generateKey(
      { name: "AES-CBC", length: 256 },
      true,
      ["encrypt"]
    );

    const iv = window.crypto.getRandomValues(new Uint8Array(16));

    const encryptedData = await window.crypto.subtle.encrypt(
      { name: "AES-CBC", iv },
      key,
      buffer
    );

    // 👉 2. ADD THESE TWO LINES TO STOP TIMER AND PRINT RESULT
    const endTime = performance.now();
    console.log(`[ENCRYPT] Size: ${(file.size / 1000000).toFixed(2)} MB | Time: ${(endTime - startTime).toFixed(2)} ms`);

    const rawKey = await window.crypto.subtle.exportKey("raw", key);

    return {
      encryptedBlob: new Blob([encryptedData]),
      rawKey,
      iv: bufferToBase64(iv)
    };
  };

  // 🚀 UPLOAD
  const uploadFile = async () => {
    if (!file) return alert("Select a file first.");

    try {
      const { encryptedBlob, rawKey, iv } = await encryptFile(file);

      const publicKeyBase64 = localStorage.getItem("publicKey");

      const publicKey = await window.crypto.subtle.importKey(
        "spki",
        Uint8Array.from(atob(publicKeyBase64), c => c.charCodeAt(0)),
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );

      const encryptedKeyBuffer = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        rawKey
      );

      const encryptedKey = bufferToBase64(encryptedKeyBuffer);

      const formData = new FormData();
      formData.append("file", encryptedBlob, file.name);
      formData.append("encryptedKey", encryptedKey);
      formData.append("iv", iv);

      await axios.post("http://localhost:5000/api/files/upload", formData, {
        headers: { Authorization: `Bearer ${token}` },
      });

      alert("Uploaded securely 🔐");
      fetchFiles();

    } catch (err) {
      console.error(err);
      alert("Upload failed");
    }
  };

  // 📥 FETCH FILES
  const fetchFiles = async () => {
    const res = await axios.get("http://localhost:5000/api/files", {
      headers: { Authorization: `Bearer ${token}` },
    });
    setFiles(res.data);
  };

  // 🔓 DOWNLOAD & DECRYPT
// 🔓 DOWNLOAD & DECRYPT
  const downloadFile = async (id) => {
    try {
      const res = await axios.get(
        `http://localhost:5000/api/files/download/${id}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );

      const { encryptedData, encryptedKey, iv, filename } = res.data;

      const encryptedBuffer = Uint8Array.from(
        atob(encryptedData),
        c => c.charCodeAt(0)
      );

      const privateKey = await getPrivateKey();

      const decryptedKeyBuffer = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        Uint8Array.from(atob(encryptedKey), c => c.charCodeAt(0))
      );

      const aesKey = await window.crypto.subtle.importKey(
        "raw",
        decryptedKeyBuffer,
        { name: "AES-CBC" },
        false,
        ["decrypt"]
      );

      // 👉 3. ADD THIS LINE STARTING THE TIMER
      const startTime = performance.now();

      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: "AES-CBC",
          iv: Uint8Array.from(atob(iv), c => c.charCodeAt(0))
        },
        aesKey,
        encryptedBuffer
      );

      // 👉 4. ADD THESE TWO LINES TO STOP TIMER AND PRINT RESULT
      const endTime = performance.now();
      console.log(`[DECRYPT] File: ${filename} | Time: ${(endTime - startTime).toFixed(2)} ms`);

      const blob = new Blob([decrypted]);
      const url = URL.createObjectURL(blob);

      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      link.click();

    } catch (err) {
      console.error(err);
      alert("Decryption failed");
    }
  };

  // 🔁 SHARE FILE
  const shareFile = async (fileId) => {
    const email = prompt("Enter email to share with:");
    if (!email) return;

    if (!privateKeyFile) {
      return alert("Upload your private key first!");
    }

    try {
      const userRes = await axios.post(
        "http://localhost:5000/api/users/get-by-email",
        { email },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      const receiver = userRes.data;

      const keyRes = await axios.get(
        `http://localhost:5000/api/files/get-key/${fileId}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );

      const { encryptedKey } = keyRes.data;

      const privateKey = await getPrivateKey();

      const decryptedKeyBuffer = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        Uint8Array.from(atob(encryptedKey), c => c.charCodeAt(0))
      );

      const receiverPublicKey = await window.crypto.subtle.importKey(
        "spki",
        Uint8Array.from(atob(receiver.publicKey), c => c.charCodeAt(0)),
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );

      const newEncryptedKeyBuffer = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        receiverPublicKey,
        decryptedKeyBuffer
      );

      const newEncryptedKey = bufferToBase64(newEncryptedKeyBuffer);

      await axios.post(
        "http://localhost:5000/api/files/share",
        {
          fileId,
          encryptedKey: newEncryptedKey,
          receiverId: receiver._id
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      alert("File shared securely 🔐");
      fetchFiles();

    } catch (error) {
      console.error(error);
      alert(error.response?.data?.message || "Sharing failed");
    }
  };

  // ❌ REVOKE
const revokeAccess = async (fileId, userId) => {
  if (!window.confirm("Revoke access?")) return;

  try {
    const res = await axios.post(
      "http://localhost:5000/api/files/revoke",
      { fileId, userId },
      { headers: { Authorization: `Bearer ${token}` } }
    );

    alert(res.data.message || "Access revoked");

    // 🔥 instant UI update (no reload lag)
    setFiles(prev =>
      prev.map(file =>
        file._id === fileId
          ? {
              ...file,
              encryptedKeys: file.encryptedKeys.filter(
                k => k.user._id !== userId
              )
            }
          : file
      )
    );

  } catch (err) {
    console.error(err);
    alert("Revoke failed");
  }
};

  const logout = () => {
    localStorage.clear();
    window.location.reload();
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  return (
    <>
      <div className="bg-orbs">
        <div className="orb orb-1"></div>
        <div className="orb orb-2"></div>
        <div className="orb orb-3"></div>
      </div>

      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "40px 20px" }}>

        {/* HEADER */}
        <header style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 40
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <FaShieldAlt size={26} />
            <h1 style={{ margin: 0, fontSize: "1.6rem", fontWeight: 600 }}>
              Nexus Vault
            </h1>
          </div>

          <button className="btn-premium secondary" onClick={logout}>
            Disconnect
          </button>
        </header>

        {/* STATS */}
        <div className="stats-grid" style={{ marginBottom: 20 }}>
          <div className="glass-panel stat-card">
            <h3>{files.length}</h3>
            <p>Encrypted Files</p>
          </div>
          <div className="glass-panel stat-card">
            <h3>AES-256</h3>
            <p>Encryption</p>
          </div>
          <div className="glass-panel stat-card">
            <h3>Secure</h3>
            <p>Connection</p>
          </div>
        </div>

        {/* 🔐 DEDICATED PRIVATE KEY ZONE */}
        <div className="glass-panel" style={{ 
          marginBottom: 20, 
          display: "flex", 
          flexDirection: "row", 
          alignItems: "center", 
          justifyContent: "space-between",
          padding: "20px"
        }}>
          <div>
            <h3 style={{ margin: "0 0 5px 0" }}>Key Configuration</h3>
            <p style={{ margin: 0, opacity: 0.8, fontSize: "0.9rem" }}>
              Choose your private key (.txt) to enable decryption and sharing.
            </p>
          </div>
          <input 
            type="file" 
            accept=".txt"
            onChange={(e) => setPrivateKeyFile(e.target.files[0])}
            style={{ 
              padding: "10px", 
              border: "1px solid rgba(255, 255, 255, 0.2)", 
              borderRadius: "8px",
              background: "rgba(0, 0, 0, 0.1)"
            }}
          />
        </div>

        {/* UPLOAD ZONE */}
        <div className="glass-panel upload-zone">
          <div style={{
            display: "flex",
            flexDirection: "column",
            gap: 10
          }}>
            <label style={{ fontWeight: 600 }}>Select File to Encrypt & Vault:</label>
            <input type="file"
              onChange={(e) => setFile(e.target.files[0])}
            />
          </div>

          <button className="btn-premium" onClick={uploadFile} style={{ marginTop: 15 }}>
            <FaCloudUploadAlt /> Upload
          </button>
        </div>

        {/* FILE GRID */}
        <div className="file-grid">
          {files.map((f) => (
            <div key={f._id} className="glass-panel file-card">

              <FaFileAlt size={28} />

              <h4 style={{ marginTop: 12 }}>{f.filename}</h4>

              <div className="badge">
                <FaLock size={12} /> Encrypted
              </div>

              <div style={{ display: "flex", gap: 10, width: "100%", flexWrap: "wrap", marginTop: "15px" }}>

                <button
                  className="btn-premium secondary"
                  style={{ flex: 1 }}
                  onClick={() => downloadFile(f._id)}
                >
                  <FaDownload /> Decrypt
                </button>

                {currentUserId === f.owner && (
                  <>
                    <button
                      className="btn-premium secondary"
                      style={{ flex: 1 }}
                      onClick={() => shareFile(f._id)}
                    >
                      <FaShare /> Share
                    </button>

                    {/* 👉 THE NEW DELETE BUTTON */}
                    <button
                      className="btn-premium secondary"
                      style={{ flex: 1, borderColor: "rgba(255, 71, 87, 0.5)", color: "#ff4757" }}
                      onClick={() => deleteFile(f._id)}
                    >
                      <FaTrash /> Delete
                    </button>

                    {/* 🔐 SHARED USERS */}
                    {currentUserId === f.owner && f.encryptedKeys?.length > 1 && (
                      <div style={{ width: "100%", marginTop: "10px" }}>
                        <p style={{ fontSize: "0.75rem", opacity: 0.7 }}>Shared With:</p>

                        {f.encryptedKeys.map((k) => {
                          const userId = k.user._id || k.user;
                          if (userId === f.owner) return null;

                          return (
                            <div
                              key={k.user._id}
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "center",
                                marginTop: "6px",
                                background: "rgba(255,255,255,0.03)",
                                padding: "6px 10px",
                                borderRadius: "8px"
                              }}
                            >
                              <span style={{ fontSize: "0.8rem" }}>
                                {k.user.email}
                              </span>

                              <button
                                className="btn-premium secondary"
                                style={{
                                  padding: "4px 10px",
                                  fontSize: "0.75rem",
                                  borderColor: "rgba(255, 71, 87, 0.5)",
                                  color: "#ff4757"
                                }}
                                onClick={() => revokeAccess(f._id, k.user._id || k.user)}
                              >
                                Revoke
                              </button>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </>
                )}

              </div>

            </div>
          ))}
        </div>

      </div>
    </>
  );
}

export default Dashboard;