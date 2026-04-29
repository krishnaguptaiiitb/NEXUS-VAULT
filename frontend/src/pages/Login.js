import { useState } from "react";
import axios from "axios";

function Login({ setIsLoggedIn, setIsLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleLogin = async () => {
    try {
      const res = await axios.post("http://localhost:5000/api/users/login", {
        email,
        password,
      });

      localStorage.setItem("token", res.data.token);
      localStorage.setItem("userId", res.data._id);
      localStorage.setItem("publicKey", res.data.publicKey);

      setIsLoggedIn(true);

    } catch (error) {
      alert(error.response?.data?.message || "Login failed");
    }
  };

  return (
    <div className="container">
      <div className="card" style={{ maxWidth: 400, margin: "auto" }}>

        <h2 style={{ marginBottom: 10 }}>Sign in</h2>
        <p style={{ color: "#64748b", marginBottom: 20 }}>
          Access your secure storage
        </p>

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

        <button className="btn btn-primary" onClick={handleLogin}>
          Login
        </button>

        <p style={{ marginTop: 15, cursor: "pointer", color: "#2563eb" }}
           onClick={() => setIsLogin(false)}>
          Create account
        </p>
      </div>
    </div>
  );
}

export default Login;