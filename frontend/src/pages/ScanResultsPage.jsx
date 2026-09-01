import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Layout } from "../components/Layout";
import { ScoreGauge } from "../components/ScoreGauge";
import { StatusBadge, SeverityBadge } from "../components/StatusBadge";
import { api } from "../services/api";

export function ScanResultsPage() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    api
      .getAssessment(id)
      .then(setData)
      .catch((e) => setError(e.message));
  }, [id]);

  if (error) {
    return (
      <Layout title="Scan Results">
        <div className="alert alert-error">{error}</div>
      </Layout>
    );
  }

  if (!data) {
    return (
      <Layout title="Scan Results">
        <div className="spinner" />
      </Layout>
    );
  }

  const counts = data.report?.severity_counts || {};

  return (
    <Layout
      title={`Scan Results — ${data.domain}`}
      subtitle={`Assessment ${data.assessment_id} · ${new Date(data.created_at).toLocaleString()}`}
      actions={
        <div style={{ display: "flex", gap: 10 }}>
          <button className="btn btn-secondary" onClick={() => navigate(`/scan/${id}/recommendations`)}>
            AI Recommendations
          </button>
          <button className="btn btn-primary" onClick={() => navigate(`/scan/${id}/report`)}>
            View Full Report
          </button>
        </div>
      }
    >
      <div className="grid grid-2" style={{ marginBottom: 24, alignItems: "stretch" }}>
        <div className="card" style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
          <ScoreGauge score={data.score} />
        </div>
        <div className="grid grid-4" style={{ gap: 12 }}>
          <div className="card stat-card">
            <span className="stat-label">Critical</span>
            <span className="stat-value" style={{ color: "var(--critical)" }}>{counts.critical || 0}</span>
          </div>
          <div className="card stat-card">
            <span className="stat-label">High</span>
            <span className="stat-value" style={{ color: "var(--high)" }}>{counts.high || 0}</span>
          </div>
          <div className="card stat-card">
            <span className="stat-label">Medium</span>
            <span className="stat-value" style={{ color: "var(--medium)" }}>{counts.medium || 0}</span>
          </div>
          <div className="card stat-card">
            <span className="stat-label">Low</span>
            <span className="stat-value" style={{ color: "var(--low)" }}>{counts.low || 0}</span>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="section-title">Security Checks</div>
        <table>
          <thead>
            <tr>
              <th>Check</th>
              <th>Status</th>
              <th>Severity</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {data.findings.map((f) => {
              const detail = data.report?.checks?.find((c) => c.check === f.check);
              return (
                <tr key={f.check}>
                  <td style={{ fontWeight: 600 }}>{f.check}</td>
                  <td><StatusBadge status={f.status} /></td>
                  <td><SeverityBadge severity={detail?.severity} /></td>
                  <td className="evidence-text">{f.evidence}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}
