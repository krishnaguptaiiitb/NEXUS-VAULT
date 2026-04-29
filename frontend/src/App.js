import { useState } from "react";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(
    !!localStorage.getItem("token")
  );
  const [isLogin, setIsLogin] = useState(true);

  if (isLoggedIn) return <Dashboard />;

  return isLogin ? (
    <Login setIsLoggedIn={setIsLoggedIn} setIsLogin={setIsLogin} />
  ) : (
    <Register setIsLogin={setIsLogin} />
  );
}

export default App;