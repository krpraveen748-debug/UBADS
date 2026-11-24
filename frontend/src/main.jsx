import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App.jsx";
import { AuthProvider } from "./auth/AuthContext.jsx";
import { DataModeProvider } from "./context/DataModeContext.jsx";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <AuthProvider>
      <DataModeProvider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </DataModeProvider>
    </AuthProvider>
  </React.StrictMode>
);
