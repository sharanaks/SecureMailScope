import { useState } from "react";

const faqs = [
  {
    question: "What does SecureMailScope check?",
    answer:
      "SecureMailScope is an email-security assessment tool that checks the publicly available security configuration of a domain. It performs checks for SPF, DKIM, DMARC, MX records, TLS/STARTTLS connectivity and mail-server certificates. The results of these checks are analyzed by the rule engine to identify security weaknesses and assign severity levels such as Critical, High, Medium and Low. These findings are then used to calculate an overall security score and provide recommendations for improving the domain's email-security configuration.",
  },

  {
    question: "Does SecureMailScope check whether a website is fake?",
    answer:
      "No. SecureMailScope does not determine whether a website is completely genuine, fake, malicious or safe. Its purpose is specifically to assess email-security controls associated with a domain. For example, it checks whether the domain has proper SPF, DKIM and DMARC configuration and whether secure mail-server connections can be established. Website reputation, phishing detection and malware detection are different types of security analysis and require additional services or checks.",
  },

  {
    question: "What is SPF?",
    answer:
      "SPF stands for Sender Policy Framework. It is an email authentication mechanism that allows a domain owner to publish a DNS record specifying which mail servers are authorized to send emails on behalf of that domain. When a receiving mail server gets an email, it can check the sender's server against the domain's SPF record. SecureMailScope checks whether an SPF record exists and examines its policy. A properly configured SPF policy helps reduce unauthorized email sending and makes domain spoofing more difficult.",
  },

  {
    question: "What is DKIM?",
    answer:
      "DKIM stands for DomainKeys Identified Mail. It uses cryptographic signatures to help verify that an email was authorized by the sending domain and that the signed message content has not been modified during transmission. The sending mail server signs the email using a private key, while the corresponding public key is published in the domain's DNS. SecureMailScope checks for DKIM records using common selectors. A valid DKIM configuration provides an additional layer of trust for outgoing email.",
  },

  {
    question: "What is DMARC?",
    answer:
      "DMARC stands for Domain-based Message Authentication, Reporting and Conformance. It works together with SPF and DKIM to protect domains from email spoofing and impersonation. A DMARC record tells receiving mail servers what to do when an email fails the required authentication checks. Common policies include none, quarantine and reject. SecureMailScope checks the domain's DMARC policy and reports its configuration and enforcement strength. A reject policy generally provides stronger protection against unauthorized use of the domain.",
  },

  {
    question: "What is an MX record?",
    answer:
      "MX stands for Mail Exchange. An MX record is a DNS record that identifies the mail servers responsible for receiving email for a domain. When someone sends an email to a domain, the sending mail system can look up the domain's MX records to determine where the message should be delivered. SecureMailScope checks whether MX records are available and identifies the configured mail-server information. This helps confirm that the domain has identifiable email-receiving infrastructure.",
  },

  {
    question: "What is TLS and why is it important?",
    answer:
      "TLS stands for Transport Layer Security. It is used to encrypt communication between systems so that information travelling across a network is protected from being easily read or modified. In email systems, mail servers can use STARTTLS to upgrade a connection to an encrypted TLS connection. SecureMailScope attempts to establish TLS/STARTTLS connections with the domain's mail servers. If the connection cannot be established, the scanner reports the issue because secure email transport could not be verified.",
  },

  {
    question: "What is an email certificate?",
    answer:
      "A TLS certificate helps a mail server establish an authenticated and encrypted TLS connection. It contains information that allows a client to verify the identity of the server and establish secure communication. SecureMailScope checks certificate availability as part of its TLS assessment. If a TLS connection cannot be established and no certificate can be obtained, the report can identify the certificate check as a security finding. Maintaining valid certificates is important for reliable encrypted mail communication.",
  },

  {
    question: "Why is my security score low?",
    answer:
      "The security score represents the result of the security checks performed during the scan. Failed or weak security controls can reduce the overall score. For example, problems with TLS connectivity or certificate availability may produce high-severity findings. The score should therefore be understood together with the individual findings shown in the report. SecureMailScope also provides recommended actions so that the domain owner can understand which areas need attention.",
  },

  {
    question: "What do Critical, High, Medium and Low mean?",
    answer:
      "Severity levels indicate how important a detected security issue is according to the scanner's rule engine. Critical findings represent the most serious issues, followed by High, Medium and Low. The severity helps users prioritize remediation instead of treating every finding equally. SecureMailScope displays the number of findings in each severity category and presents the higher-severity findings prominently in the security report.",
  },

  {
    question: "Why does SecureMailScope use blockchain?",
    answer:
      "Blockchain is used to provide tamper-evident verification for the security report. After a scan, SecureMailScope creates a SHA-256 hash, which acts like a digital fingerprint of the report. Instead of storing the complete report on the blockchain, the hash is recorded through the AuditRegistry smart contract. Later, the report can be hashed again and compared with the previously recorded blockchain hash. If the values match, the report's integrity can be verified.",
  },

  {
    question: "Can someone modify my security report?",
    answer:
      "A report file or stored report could potentially be modified, but SecureMailScope is designed to detect such changes through hash verification. The system generates a SHA-256 hash from the report. Even a small change to the report, such as changing a security score from 65 to 90, changes the resulting hash. During verification, SecureMailScope calculates the current hash and compares it with the previously anchored blockchain hash. If they are different, the integrity check will fail.",
  },

  {
    question: "What does Integrity Verified mean?",
    answer:
      "Integrity Verified means that the SHA-256 hash calculated from the current report matches the hash that was generated when the report was originally recorded and anchored. In other words, the report content has not changed in a way that affects the hash since it was anchored. The verification page displays both the expected hash and the actual calculated hash so the user can see that they match.",
  },

  {
    question: "What happens if the report is modified?",
    answer:
      "If the report is modified after its hash has been anchored, the current report will produce a different SHA-256 hash. SecureMailScope compares this new hash with the original hash stored through the blockchain. Because the values will no longer match, the system can show an integrity failure. This demonstrates the purpose of blockchain in the project: it provides a persistent reference against which the authenticity of the report can be checked.",
  },

  {
    question: "What is the purpose of the security report?",
    answer:
      "The security report provides a detailed record of the domain's email-security assessment. It contains the overall security score, individual check results, severity levels and evidence collected during the scan. It also provides explanations and recommended actions for detected issues. The report can then be verified using its SHA-256 hash and blockchain record, providing additional confidence that the report has not been modified after assessment.",
  },

  {
    question: "Is the scan a complete security audit?",
    answer:
      "No. SecureMailScope performs a passive assessment using publicly observable DNS and TLS information available at scan time. It is not a complete penetration test, vulnerability assessment or comprehensive security audit. A passing result does not guarantee that a domain has no security vulnerabilities. The purpose of the scan is to identify specific email-security configuration issues and provide useful recommendations based on the checks performed.",
  },
];

export default function FAQPage() {
  const [openIndex, setOpenIndex] = useState(null);

  const toggleFAQ = (index) => {
    setOpenIndex(openIndex === index ? null : index);
  };

  return (
    <div className="faq-page">
      <div className="faq-header">
        <h1>Frequently Asked Questions</h1>
        <p>
          Find answers to common questions about domains, email security and
          SecureMailScope.
        </p>
      </div>

      <div className="faq-list">
        {faqs.map((faq, index) => (
          <div className="faq-item" key={index}>
            <button
              className="faq-question"
              onClick={() => toggleFAQ(index)}
            >
              <span>{faq.question}</span>
              <span className="faq-arrow">
                {openIndex === index ? "▲" : "▼"}
              </span>
            </button>

            {openIndex === index && (
              <div className="faq-answer">
                {faq.answer}
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="faq-support">
        <div>
          <h2>Still have questions?</h2>
          <p>
            Learn more about email security and SecureMailScope.
          </p>
        </div>
      </div>
    </div>
  );
}