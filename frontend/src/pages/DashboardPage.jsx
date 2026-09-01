import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Layout } from "../components/Layout";
import { api } from "../services/api";

export function DashboardPage() {
  const [assessments, setAssessments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    api
      .listAssessments()
      .then(setAssessments)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const latest = assessments[0];
  const avgScore = assessments.length
    ? Math.round(assessments.reduce((sum, a) => sum + a.score, 0) / assessments.length)
    : null;
  const anchoredCount = assessments.filter((a) => a.blockchain_status === "anchored").length;

  return (
    <Layout
      title="Dashboard"
      subtitle="Overview of your domain security assessments"
      actions={
        <button className="btn btn-primary" onClick={() => navigate("/scan/new")}>
          + New Scan
        </button>
      }
    >
      {error && <div className="alert alert-error">{error}</div>}

      <div className="grid grid-4" style={{ marginBottom: 24 }}>
        <div className="card stat-card">
          <span className="stat-label">Total Scans</span>
          <span className="stat-value">{assessments.length}</span>
        </div>
        <div className="card stat-card">
          <span className="stat-label">Average Score</span>
          <span className="stat-value">{avgScore ?? "—"}</span>
        </div>
        <div className="card stat-card">
          <span className="stat-label">Latest Domain</span>
          <span className="stat-value" style={{ fontSize: "1.2rem" }}>
            {latest ? latest.domain : "—"}
          </span>
        </div>
        <div className="card stat-card">
          <span className="stat-label">Blockchain Anchored</span>
          <span className="stat-value">{anchoredCount}</span>
        </div>
      </div>

      <div className="card">
        <div className="section-title">Recent Assessments</div>
        {loading ? (
          <div className="spinner" />
        ) : assessments.length === 0 ? (
          <div className="empty-state">
            No scans yet. Start your first assessment to see results here.
            <div style={{ marginTop: 16 }}>
              <button className="btn btn-primary" onClick={() => navigate("/scan/new")}>
                Run your first scan
              </button>
            </div>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Score</th>
                <th>Date</th>
                <th>Blockchain</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {assessments.slice(0, 8).map((a) => (
                <tr key={a.assessment_id}>
                  <td>{a.domain}</td>
                  <td>{a.score}/100</td>
                  <td>{new Date(a.created_at).toLocaleString()}</td>
                  <td style={{ textTransform: "capitalize" }}>
                    {a.blockchain_status.replace("_", " ")}
                  </td>
                  <td>
                    <button
                      className="btn btn-secondary"
                      onClick={() => navigate(`/scan/${a.assessment_id}/results`)}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Layout>
  );
}
