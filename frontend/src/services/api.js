const API_BASE =
  import.meta.env.VITE_API_BASE || "http://localhost:8000";

function authHeaders() {
  const token = localStorage.getItem("sms_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
      ...(options.headers || {}),
    },
  });

  let data = null;

  try {
    data = await res.json();
  } catch {
    // no body
  }

  if (!res.ok) {
    const message =
      data?.detail || res.statusText || "Request failed";

    throw new Error(
      typeof message === "string"
        ? message
        : JSON.stringify(message)
    );
  }

  return data;
}

export const api = {
  // Health
  health: () => request("/api/health"),

  // Authentication
  register: (email, password) =>
    request("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        email,
        password,
      }),
    }),

  login: (email, password) =>
    request("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email,
        password,
      }),
    }),

  // Security Scan
  scan: (domain, dkimSelector) =>
    request("/api/scan", {
      method: "POST",
      body: JSON.stringify({
        domain,
        dkim_selector: dkimSelector || null,
      }),
    }),

  // Assessments
  listAssessments: () =>
    request("/api/assessments"),

  getAssessment: (id) =>
    request(`/api/assessments/${id}`),

  // Reports
  getReport: (id) =>
    request(`/api/reports/${id}`),

  verifyReport: (id, report) =>
    request(`/api/reports/${id}/verify`, {
      method: "POST",
      body: JSON.stringify(
        report ? { report } : {}
      ),
    }),

  // Blockchain
  anchorAssessment: (id) =>
    request(`/api/blockchain/anchor/${id}`, {
      method: "POST",
    }),

  blockchainStatus: (id) =>
    request(`/api/blockchain/status/${id}`),

  // AI Security Assistant
  chat: (question, assessmentId = null) =>
    request("/api/chat", {
      method: "POST",
      body: JSON.stringify({
        question,
        assessment_id: assessmentId,
      }),
    }),
};