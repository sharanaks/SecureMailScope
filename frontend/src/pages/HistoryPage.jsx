import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Layout } from "../components/Layout";
import { api } from "../services/api";

export function HistoryPage() {
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

  return (
    <Layout
      title="Scan History"
      subtitle="All previous security assessments"
      actions={
        <button className="btn btn-primary" onClick={() => navigate("/scan/new")}>
          + New Scan
        </button>
      }
    >
      {error && <div className="alert alert-error">{error}</div>}
      <div className="card">
        {loading ? (
          <div className="spinner" />
        ) : assessments.length === 0 ? (
          <div className="empty-state">No assessments yet.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Assessment ID</th>
                <th>Domain</th>
                <th>Score</th>
                <th>Date</th>
                <th>Blockchain</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {assessments.map((a) => (
                <tr key={a.assessment_id}>
                  <td style={{ fontFamily: "monospace", fontSize: "0.78rem" }}>
                    {a.assessment_id.slice(0, 8)}...
                  </td>
                  <td>{a.domain}</td>
                  <td>{a.score}/100</td>
                  <td>{new Date(a.created_at).toLocaleString()}</td>
                  <td style={{ textTransform: "capitalize" }}>{a.blockchain_status.replace("_", " ")}</td>
                  <td>
                    <button
                      className="btn btn-secondary"
                      onClick={() => navigate(`/scan/${a.assessment_id}/results`)}
                    >
                      Open
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
