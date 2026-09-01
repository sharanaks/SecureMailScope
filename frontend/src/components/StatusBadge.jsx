export function StatusBadge({ status }) {
  const cls = {
    PASS: "badge-pass",
    WARNING: "badge-warning",
    FAIL: "badge-fail",
  }[status] || "badge-warning";

  return <span className={`badge ${cls}`}>{status}</span>;
}

export function SeverityBadge({ severity }) {
  if (!severity) return null;
  const cls = `badge-${severity.toLowerCase()}`;
  return <span className={`badge ${cls}`}>{severity}</span>;
}
