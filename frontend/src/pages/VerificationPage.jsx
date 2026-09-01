import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { Layout } from "../components/Layout";
import { api } from "../services/api";

export function VerificationPage() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [status, setStatus] = useState(null);
  const [anchoring, setAnchoring] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [error, setError] = useState("");

  function loadStatus() {
    api.blockchainStatus(id).then(setStatus).catch((e) => setError(e.message));
  }

  useEffect(() => {
    api.getAssessment(id).then(setData).catch((e) => setError(e.message));
    loadStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  async function handleAnchor() {
    setAnchoring(true);
    setError("");
    try {
      await api.anchorAssessment(id);
      loadStatus();
    } catch (err) {
      setError(err.message);
    } finally {
      setAnchoring(false);
    }
  }

  async function handleVerify() {
    setError("");
    try {
      const result = await api.verifyReport(id);
      setVerifyResult(result);
    } catch (err) {
      setError(err.message);
    }
  }

  if (!data || !status) {
    return (
      <Layout title="Blockchain Verification">
        <div className="spinner" />
      </Layout>
    );
  }

  const isAnchored = status.blockchain_status === "anchored";

  return (
    <Layout
      title="Blockchain Verification"
      subtitle={`Assessment ${id} — tamper-evidence via on-chain hash anchoring`}
    >
      {error && <div className="alert alert-error">{error}</div>}

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="section-title">Report Hash</div>
        <div className="hash-box" style={{ marginBottom: 14 }}>{data.report_hash}</div>

        <div className="section-title">Blockchain Status</div>
        <p>
          <span
            className={`badge ${isAnchored ? "badge-pass" : status.blockchain_status === "failed" ? "badge-fail" : "badge-warning"}`}
          >
            {status.blockchain_status === "anchored"
              ? "Anchored"
              : status.blockchain_status === "failed"
              ? "Anchoring Failed"
              : "Not Anchored"}
          </span>
        </p>

        {isAnchored ? (
          <>
            <div style={{ marginTop: 14 }}>
              <div className="section-title" style={{ fontSize: "0.9rem" }}>Transaction Hash</div>
              <div className="hash-box">{status.transaction_hash}</div>
            </div>
            {status.onchain_record && (
              <p style={{ marginTop: 10, fontSize: "0.85rem", color: "var(--text-1)" }}>
                On-chain hash matches stored report hash:{" "}
                <strong style={{ color: status.onchain_hash_matches ? "var(--pass)" : "var(--fail)" }}>
                  {status.onchain_hash_matches ? "Yes" : "No"}
                </strong>
              </p>
            )}
          </>
        ) : (
          <button className="btn btn-primary" style={{ marginTop: 14 }} onClick={handleAnchor} disabled={anchoring}>
            {anchoring ? "Anchoring on blockchain..." : "Anchor Report Hash on Blockchain"}
          </button>
        )}

        {!isAnchored && (
          <p style={{ marginTop: 10, fontSize: "0.8rem", color: "var(--text-2)" }}>
            Requires a local Hardhat node running and the contract deployed with its address set
            in backend/.env. See the README for setup steps.
          </p>
        )}
      </div>

      <div className="card">
        <div className="section-title">Verify Report Integrity</div>
        <p className="evidence-text" style={{ marginBottom: 14 }}>
          Recomputes the SHA-256 hash of the stored report and compares it against the hash
          generated at scan time (and anchored on-chain, if applicable).
        </p>
        <button className="btn btn-secondary" onClick={handleVerify}>
          Run Verification
        </button>

        {verifyResult && (
          <div
            className={`alert ${verifyResult.verified ? "alert-success" : "alert-error"}`}
            style={{ marginTop: 16 }}
          >
            <strong>{verifyResult.status}</strong>
            <div style={{ marginTop: 8, fontSize: "0.8rem" }}>
              <div>Expected: {verifyResult.expected_hash}</div>
              <div>Actual: {verifyResult.actual_hash}</div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
