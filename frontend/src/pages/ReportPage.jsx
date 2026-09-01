import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Layout } from "../components/Layout";
import { StatusBadge, SeverityBadge } from "../components/StatusBadge";
import { api } from "../services/api";

export function ReportPage() {
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

  function handleDownload() {
    const blob = new Blob([JSON.stringify(data.report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `securemailscope-report-${data.assessment_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (error) {
    return (
      <Layout title="Security Report">
        <div className="alert alert-error">{error}</div>
      </Layout>
    );
  }
  if (!data) {
    return (
      <Layout title="Security Report">
        <div className="spinner" />
      </Layout>
    );
  }

  const report = data.report;

  return (
    <Layout
      title="Security Report"
      subtitle={`Assessment ${data.assessment_id}`}
      actions={
        <div style={{ display: "flex", gap: 10 }}>
          <button className="btn btn-secondary" onClick={handleDownload}>
            Download JSON
          </button>
          <button className="btn btn-primary" onClick={() => navigate(`/scan/${id}/verify`)}>
            Blockchain Verification
          </button>
        </div>
      }
    >
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="grid grid-4">
          <div className="stat-card">
            <span className="stat-label">Domain</span>
            <span className="stat-value" style={{ fontSize: "1.2rem" }}>{report.domain}</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Overall Score</span>
            <span className="stat-value">{report.overall_score}/100</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Generated</span>
            <span className="stat-value" style={{ fontSize: "1rem" }}>
              {new Date(report.generated_at).toLocaleString()}
            </span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Assessment ID</span>
            <span className="stat-value" style={{ fontSize: "0.85rem", wordBreak: "break-all" }}>
              {report.assessment_id}
            </span>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="section-title">Findings</div>
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
            {report.checks.map((c) => (
              <tr key={c.check}>
                <td style={{ fontWeight: 600 }}>{c.check}</td>
                <td><StatusBadge status={c.status} /></td>
                <td><SeverityBadge severity={c.severity} /></td>
                <td className="evidence-text">{c.evidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="section-title">AI Explanation ({report.ai_explanation.source === "llm" ? "LLM" : "Template fallback"})</div>
        <p className="evidence-text">{report.ai_explanation.overall_summary}</p>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="section-title">Disclaimer</div>
        <p className="evidence-text">{report.disclaimer}</p>
      </div>

      <div className="card">
        <div className="section-title">Report Integrity Hash (SHA-256)</div>
        <div className="hash-box">{data.report_hash}</div>
      </div>
    </Layout>
  );
}
