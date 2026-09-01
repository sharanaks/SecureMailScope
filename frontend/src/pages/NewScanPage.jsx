import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Layout } from "../components/Layout";
import { api } from "../services/api";

export function NewScanPage() {
  const [domain, setDomain] = useState("");
  const [dkimSelector, setDkimSelector] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const result = await api.scan(domain, dkimSelector);
      navigate(`/scan/${result.assessment_id}/results`);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <Layout title="New Security Scan" subtitle="Assess an authorized domain's email security posture">
      <div className="alert alert-info">
        Only scan domains you own or are explicitly authorized to assess. This tool performs
        passive, public DNS and TLS checks only — it never reads private email or exploits
        systems.
      </div>

      <div className="card" style={{ maxWidth: 520 }}>
        {error && <div className="alert alert-error">{error}</div>}
        <form onSubmit={handleSubmit}>
          <div className="field">
            <label>Domain</label>
            <input
              type="text"
              placeholder="example.com"
              required
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
            />
          </div>
          <div className="field">
            <label>DKIM selector (optional)</label>
            <input
              type="text"
              placeholder="e.g. google, selector1 — leave blank to try common selectors"
              value={dkimSelector}
              onChange={(e) => setDkimSelector(e.target.value)}
            />
          </div>
          <button className="btn btn-primary" style={{ width: "100%" }} disabled={loading}>
            {loading ? "Scanning..." : "Start Security Scan"}
          </button>
        </form>
        {loading && (
          <p style={{ marginTop: 14, color: "var(--text-2)", fontSize: "0.85rem" }}>
            Running SPF, DMARC, DKIM, MX, and TLS/certificate checks — this can take a few
            seconds depending on the mail servers' response time.
          </p>
        )}
      </div>
    </Layout>
  );
}
