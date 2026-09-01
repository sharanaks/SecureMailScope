import { useNavigate } from "react-router-dom";

export function LandingPage() {
  const navigate = useNavigate();

  return (
    <div className="landing-hero">
      <div className="brand" style={{ justifyContent: "center", marginBottom: 24 }}>
        <div className="brand-mark">SM</div>
        SecureMailScope
      </div>
      <h1>Know your domain's real email security posture — in minutes.</h1>
      <p>
        SecureMailScope runs safe, passive checks of SPF, DKIM, DMARC, MX, and TLS/certificate
        configuration for domains you own or are authorized to assess, scores the results with a
        transparent rule engine, explains the findings in plain language, and anchors a
        tamper-evident hash of the report on a local blockchain.
      </p>
      <div className="hero-actions">
        <button className="btn btn-primary" onClick={() => navigate("/register")}>
          Get started
        </button>
        <button className="btn btn-secondary" onClick={() => navigate("/login")}>
          Log in
        </button>
      </div>

      <div className="feature-strip">
        <div className="card">
          <div className="section-title">Passive & safe</div>
          <p className="evidence-text">
            Only public DNS lookups and standard TLS handshakes. No exploitation, no email
            reading, no password collection.
          </p>
        </div>
        <div className="card">
          <div className="section-title">Deterministic scoring</div>
          <p className="evidence-text">
            Severity and score come from a documented rule engine — reproducible every time, never
            decided by AI.
          </p>
        </div>
        <div className="card">
          <div className="section-title">Tamper-evident reports</div>
          <p className="evidence-text">
            Each report is SHA-256 hashed and can be anchored on a local blockchain for
            independent integrity verification.
          </p>
        </div>
      </div>
    </div>
  );
}
