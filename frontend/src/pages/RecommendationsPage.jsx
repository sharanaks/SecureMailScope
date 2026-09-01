import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Layout } from "../components/Layout";
import { StatusBadge } from "../components/StatusBadge";
import { api } from "../services/api";

export function RecommendationsPage() {
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
      <Layout title="AI Recommendations">
        <div className="alert alert-error">{error}</div>
      </Layout>
    );
  }
  if (!data) {
    return (
      <Layout title="AI Recommendations">
        <div className="spinner" />
      </Layout>
    );
  }

  const ai = data.ai_explanation;
  const isFallback = data.ai_source === "fallback_template";

  return (
    <Layout
      title="AI Recommendations"
      subtitle={`${data.domain} — plain-language explanations of the findings above`}
      actions={
        <button className="btn btn-secondary" onClick={() => navigate(`/scan/${id}/results`)}>
          Back to Results
        </button>
      }
    >
      <div className={`alert ${isFallback ? "alert-info" : "alert-success"}`}>
        {isFallback
          ? "Generated using the built-in deterministic template engine (no AI API key configured). Severity and score were already fixed by the rule engine before this step."
          : "Generated using the configured LLM. Severity and score were already fixed by the deterministic rule engine — the AI only explains and recommends fixes."}
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="section-title">Overall Summary</div>
        <p className="evidence-text" style={{ fontSize: "0.95rem" }}>{ai?.overall_summary}</p>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr", gap: 16 }}>
        {ai?.per_finding?.map((f) => (
          <div className="card" key={f.check}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <div className="section-title" style={{ margin: 0 }}>{f.check}</div>
              <StatusBadge status={f.status || data.findings.find((x) => x.check === f.check)?.status} />
            </div>
            <p className="evidence-text" style={{ marginBottom: 10 }}>{f.simple_explanation}</p>
            <p style={{ fontSize: "0.85rem", marginBottom: 6 }}>
              <strong>Why it matters:</strong> <span className="evidence-text">{f.why_it_matters}</span>
            </p>
            <p style={{ fontSize: "0.85rem" }}>
              <strong>Recommended action:</strong> <span className="evidence-text">{f.recommendation}</span>
            </p>
          </div>
        ))}
      </div>
    </Layout>
  );
}
