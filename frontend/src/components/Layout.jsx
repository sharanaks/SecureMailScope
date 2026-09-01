import { NavLink, useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { clearSession, getEmail } from "../utils/auth";

const NAV_ITEMS = [
  { to: "/dashboard", label: "Dashboard", icon: "\u25A4" },
  { to: "/scan/new", label: "New Scan", icon: "\u2295" },
  { to: "/history", label: "Scan History", icon: "\u29D6" },
  { to: "/faq", label: "FAQ", icon: "?" },
];

export function Layout({ children, title, subtitle, actions }) {
  const navigate = useNavigate();
  const email = getEmail();

  const [darkMode, setDarkMode] = useState(() => {
    return localStorage.getItem("securemailscope-theme") !== "light";
  });

  useEffect(() => {
    document.documentElement.setAttribute(
      "data-theme",
      darkMode ? "dark" : "light"
    );

    localStorage.setItem(
      "securemailscope-theme",
      darkMode ? "dark" : "light"
    );
  }, [darkMode]);

  function handleLogout() {
    clearSession();
    navigate("/login");
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">SM</div>
          SecureMailScope
        </div>

        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `nav-link${isActive ? " active" : ""}`
            }
          >
            <span>{item.icon}</span>
            {item.label}
          </NavLink>
        ))}

        <div style={{ marginTop: "auto", paddingTop: 20 }}>
          <button
            className="btn btn-secondary"
            style={{ width: "100%", marginBottom: 12 }}
            onClick={() => setDarkMode(!darkMode)}
          >
            {darkMode ? "☀️ Light Mode" : "🌙 Dark Mode"}
          </button>

          {email && (
            <div
              style={{
                fontSize: "0.78rem",
                color: "var(--text-2)",
                padding: "0 8px 10px",
              }}
            >
              {email}
            </div>
          )}

          <button
            className="btn btn-secondary"
            style={{ width: "100%" }}
            onClick={handleLogout}
          >
            Log out
          </button>
        </div>
      </aside>

      <main className="main-content">
        {(title || actions) && (
          <div className="topbar">
            <div>
              {title && <h1 className="page-title">{title}</h1>}
              {subtitle && <p className="page-subtitle">{subtitle}</p>}
            </div>

            {actions}
          </div>
        )}

        {children}
      </main>
    </div>
  );
}