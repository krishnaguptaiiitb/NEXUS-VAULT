import { useState } from "react";
import axios from "axios";

function Register({ setIsLogin }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

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

    const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    return {
      publicKey: btoa(String.fromCharCode(...new Uint8Array(publicKey))),
      privateKey: btoa(String.fromCharCode(...new Uint8Array(privateKey)))
    };
  };

  const handleRegister = async () => {
    try {
      const { publicKey, privateKey } = await generateKeys();

      localStorage.setItem("privateKey", privateKey);

      await axios.post("http://localhost:5000/api/users/register", {
        name,
        email,
        password,
        publicKey
      });

      alert("Account created successfully");
      setIsLogin(true);

    } catch {
      alert("Registration failed");
    }
  };

  return (
    <div className="container">
      <div className="card" style={{ maxWidth: 400, margin: "auto" }}>

        <h2>Create account</h2>

        <input
          className="input"
          placeholder="Name"
          onChange={(e) => setName(e.target.value)}
        />

        <input
          className="input"
          placeholder="Email"
          onChange={(e) => setEmail(e.target.value)}
        />

        <input
          className="input"
          type="password"
          placeholder="Password"
          onChange={(e) => setPassword(e.target.value)}
        />

        <button className="btn btn-primary" onClick={handleRegister}>
          Register
        </button>

        <p style={{ marginTop: 15, cursor: "pointer", color: "#2563eb" }}
           onClick={() => setIsLogin(true)}>
          Already have account?
        </p>
      </div>
    </div>
  );
}

export default Register;