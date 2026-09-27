import { useState } from "react";
import { Layout } from "../components/Layout";
import { api } from "../services/api";

const SUGGESTED_QUESTIONS = [
  "What is SPF?",
  "What is DKIM?",
  "What is DMARC?",
  "What is email spoofing?",
  "How does blockchain verify my report?",
  "What is TLS?",
];

export function AIAssistantPage() {
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content:
        "Hello! 👋 I'm your SecureMailScope AI Assistant. Ask me anything about cybersecurity, email security, programming, technology, or your scan results.",
    },
  ]);

  const [question, setQuestion] = useState("");
  const [loading, setLoading] = useState(false);

  async function sendQuestion(text = question) {
    const cleanQuestion = text.trim();

    if (!cleanQuestion || loading) {
      return;
    }

    setMessages((previous) => [
      ...previous,
      {
        role: "user",
        content: cleanQuestion,
      },
    ]);

    setQuestion("");
    setLoading(true);

    try {
      const response = await api.chat(cleanQuestion);

      setMessages((previous) => [
        ...previous,
        {
          role: "assistant",
          content:
            response.answer ||
            "Sorry, I could not generate an answer.",
        },
      ]);
    } catch (error) {
      setMessages((previous) => [
        ...previous,
        {
          role: "assistant",
          content:
            error.message ||
            "Unable to contact the AI Assistant.",
        },
      ]);
    } finally {
      setLoading(false);
    }
  }

  function handleSubmit(event) {
    event.preventDefault();
    sendQuestion();
  }

  return (
    <Layout
      title="AI Security Assistant"
      subtitle="Your intelligent companion for cybersecurity and more"
    >
      <div className="ai-page">

        {/* Hero */}
        <div className="ai-hero">
          <div className="ai-hero-icon">
            ✨
          </div>

          <div className="ai-hero-content">
            <div className="ai-hero-title">
              SecureMailScope AI
            </div>

            <div className="ai-hero-subtitle">
              Ask questions, understand your security, and explore
              cybersecurity with AI.
            </div>
          </div>

          <div className="ai-status">
            <span className="ai-status-dot" />
            Online
          </div>
        </div>

        {/* Chat Card */}
        <div className="ai-chat-card">

          {/* Chat Header */}
          <div className="ai-chat-header">
            <div className="ai-profile">
              <div className="ai-avatar">
                🛡️
              </div>

              <div>
                <div className="ai-name">
                  Security Assistant
                </div>

                <div className="ai-online">
                  <span />
                  Ready to help
                </div>
              </div>
            </div>

            <div className="ai-model-badge">
              Claude AI
            </div>
          </div>

          {/* Suggested Questions */}
          <div className="ai-suggestions">
            <div className="ai-suggestions-title">
              <span>💡</span>
              Try asking
            </div>

            <div className="ai-suggestion-list">
              {SUGGESTED_QUESTIONS.map((item) => (
                <button
                  key={item}
                  type="button"
                  className="ai-suggestion"
                  onClick={() => sendQuestion(item)}
                  disabled={loading}
                >
                  {item}
                </button>
              ))}
            </div>
          </div>

          {/* Messages */}
          <div className="ai-messages">
            {messages.map((message, index) => {
              const isUser = message.role === "user";

              return (
                <div
                  key={index}
                  className={`ai-message-row ${
                    isUser ? "user" : "assistant"
                  }`}
                >
                  {!isUser && (
                    <div className="ai-small-avatar">
                      🤖
                    </div>
                  )}

                  <div
                    className={`ai-message ${
                      isUser ? "user" : "assistant"
                    }`}
                  >
                    <div className="ai-message-label">
                      {isUser ? "YOU" : "AI ASSISTANT"}
                    </div>

                    <div className="ai-message-text">
                      {message.content}
                    </div>
                  </div>

                  {isUser && (
                    <div className="user-small-avatar">
                      👤
                    </div>
                  )}
                </div>
              );
            })}

            {/* Thinking */}
            {loading && (
              <div className="ai-message-row assistant">
                <div className="ai-small-avatar">
                  🤖
                </div>

                <div className="ai-message assistant thinking-message">
                  <div className="ai-message-label">
                    AI ASSISTANT
                  </div>

                  <div className="thinking">
                    <span />
                    <span />
                    <span />
                    <label>Thinking...</label>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Input */}
          <form
            className="ai-input-area"
            onSubmit={handleSubmit}
          >
            <div className="ai-input-wrapper">
              <span className="ai-input-icon">
                ✨
              </span>

              <input
                type="text"
                value={question}
                onChange={(event) =>
                  setQuestion(event.target.value)
                }
                placeholder="Ask me anything..."
                disabled={loading}
              />

              <button
                className="ai-send-button"
                type="submit"
                disabled={
                  loading || !question.trim()
                }
                title="Send message"
              >
                {loading ? "..." : "➤"}
              </button>
            </div>
          </form>
        </div>

        {/* Footer */}
        <div className="ai-footer">
          <span>🔒</span>
          SecureMailScope AI provides assistance based on available
          information. Always verify critical security decisions.
        </div>
      </div>
    </Layout>
  );
}