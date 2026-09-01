export function ScoreGauge({ score, size = 160 }) {
  const radius = (size - 20) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const dash = circumference * pct;

  let color = "#2ecc71";
  if (score < 40) color = "#ff5c5c";
  else if (score < 70) color = "#f5a623";

  return (
    <div className="gauge-wrap">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#24314d"
          strokeWidth="14"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="14"
          strokeDasharray={`${dash} ${circumference}`}
          strokeLinecap="round"
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
        <text
          x="50%"
          y="48%"
          textAnchor="middle"
          fontSize="34"
          fontWeight="800"
          fill="#eef2ff"
        >
          {score}
        </text>
        <text
          x="50%"
          y="64%"
          textAnchor="middle"
          fontSize="12"
          fill="#8391b3"
        >
          / 100
        </text>
      </svg>
    </div>
  );
}
