import React, { useEffect, useState } from "react"
import { createRoot } from "react-dom/client"
import "./style.css"

const API = "http://127.0.0.1:8000"

const TEMPLATES = [
  {
    name: "Microsoft Security Alert",
    sender: "security-alert@microsoft-support-login.com",
    recipient: "ceo@mycompany.com",
    subject: "Action Required: Unusual login activity detected",
    body: "We detected a suspicious login to your Microsoft Office 365 account from IP 192.168.4.15. Click here to confirm your identity or change your password immediately: http://microsoft-support-login.com/auth/verify?id=928",
  },
  {
    name: "Spear-Phishing Anomaly",
    sender: "hr-system@mycompany-internal.com",
    recipient: "employee@mycompany.com",
    subject: "URGENT: Verify your payroll credentials",
    body: "Please verify your payroll information within 10 minutes to avoid a payout delay. Confirm your credentials: http://payroll-portal.com/login",
    headers: "{\"behavior_anomaly\": \"0.85\"}" // Sender behavior anomaly signal
  },
  {
    name: "Suspicious Urgent Invoice",
    sender: "finance-dept@external-vendors.com",
    recipient: "accounts-payable@mycompany.com",
    subject: "Payment Overdue: Invoice #20391",
    body: "Your transfer for invoice #20391 is overdue. Payment is required immediately. Please review and process the invoice. Link: http://invoices.net/pay",
  },
  {
    name: "Safe Calendar Sync",
    sender: "colleague@mycompany.com",
    recipient: "you@mycompany.com",
    subject: "Project Aegis kickoff meeting sync",
    body: "Hi all, I scheduled a kickoff meeting for the new project tomorrow at 2 PM in Room B. Let's sync up then. Thanks!",
  }
]

function App() {
  const [form, setForm] = useState({
    sender: TEMPLATES[0].sender,
    recipient: TEMPLATES[0].recipient,
    subject: TEMPLATES[0].subject,
    body: TEMPLATES[0].body,
    headers: TEMPLATES[0].headers || "",
  })
  const [result, setResult] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(false)
  const [activeTab, setActiveTab] = useState("severity") // "severity" | "signals" | "urls"

  const [fallbackMode, setFallbackMode] = useState(true)

  const refresh = async () => {
    try {
      const [a, s, h] = await Promise.all([
        fetch(`${API}/api/alerts`).then(r => r.json()),
        fetch(`${API}/api/stats`).then(r => r.json()),
        fetch(`${API}/api/health`).then(r => r.json()).catch(() => ({ fallback_mode: true }))
      ])
      setAlerts(a)
      setStats(s)
      setFallbackMode(!!h.fallback_mode)
    } catch (e) {
      console.error("Failed to fetch dashboard data:", e)
    }
  }

  useEffect(() => {
    refresh()
  }, [])

  const analyze = async () => {
    setLoading(true)
    try {
      let parsedHeaders = {}
      if (form.headers) {
        try {
          parsedHeaders = JSON.parse(form.headers)
        } catch {
          // If custom key-value isn't json, treat it as a header dict directly or raw
          parsedHeaders = { "custom_data": form.headers }
        }
      }

      const response = await fetch(`${API}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sender: form.sender,
          recipient: form.recipient,
          subject: form.subject,
          body: form.body,
          headers: parsedHeaders,
          attachments: [] // Standard prototype email
        })
      })
      const data = await response.json()
      setResult(data)
      setActiveTab("severity") // reset tab to default
      refresh()
    } catch (err) {
      console.error("Analysis request failed:", err)
    } finally {
      setLoading(false)
    }
  }

  const update = e => setForm({ ...form, [e.target.name]: e.target.value })

  const loadTemplate = t => {
    setForm({
      sender: t.sender,
      recipient: t.recipient,
      subject: t.subject,
      body: t.body,
      headers: t.headers || "",
    })
  }

  const inspectIncident = incident => {
    setForm({
      sender: incident.sender,
      recipient: "recipient@company.com", // Fallback
      subject: incident.subject,
      body: "Historical Threat Context. (Re-run analysis below)", // Placeholder body for details
      headers: JSON.stringify(incident.signals || {}),
    })
    // Display the historical result directly
    setResult(incident)
    setActiveTab("severity")
  }

  const signalData = result?.signals || {}
  const riskScore = Number(result?.risk_score ?? 0)

  return (
    <div className="page">
      <header>
        <div className="logo-block">
          <h1>AEGIS <span className="logo-badge">Prototype</span></h1>
          <p>Real-Time Phishing & Threat Intelligence Dashboard</p>
        </div>
        <div className="header-status">
          <span className="pulse-indicator" style={{
            backgroundColor: fallbackMode ? 'var(--color-suspicious)' : 'var(--color-safe)',
            boxShadow: fallbackMode ? '0 0 10px var(--color-suspicious)' : '0 0 10px var(--color-safe)'
          }}></span>
          <span>Aegis Core active ({fallbackMode ? "Fallback Mode" : "BERT & XGBoost active"})</span>
        </div>
      </header>

      {stats && (
        <section className="stats">
          <div className="card card-total">
            <span>Total Inspected</span>
            <strong>{stats.total}</strong>
          </div>
          <div className="card card-safe">
            <span>Legitimate</span>
            <strong>{stats.safe}</strong>
          </div>
          <div className="card card-suspicious">
            <span>Suspicious</span>
            <strong>{stats.suspicious}</strong>
          </div>
          <div className="card card-phishing">
            <span>Phishing</span>
            <strong>{stats.phishing}</strong>
          </div>
          <div className="card card-spear">
            <span>Spear-Phishing</span>
            <strong>{stats.spear_phishing}</strong>
          </div>
        </section>
      )}

      <main>
        {/* Left Panel: Analysis controls */}
        <section className="panel">
          <h2>Email Analysis Lab</h2>

          {/* Quick templates grid */}
          <div className="templates-container">
            <label>Load Pre-Defined Threat Scenarios</label>
            <div className="templates-grid">
              {TEMPLATES.map((t, idx) => (
                <button key={idx} className="template-btn" onClick={() => loadTemplate(t)}>
                  🔍 {t.name}
                </button>
              ))}
            </div>
          </div>

          <div className="form-group">
            <label>Sender Envelope Address</label>
            <input name="sender" value={form.sender} onChange={update} placeholder="sender@domain.com" />
          </div>

          <div className="form-group">
            <label>Recipient Address</label>
            <input name="recipient" value={form.recipient} onChange={update} placeholder="recipient@domain.com" />
          </div>

          <div className="form-group">
            <label>Email Subject</label>
            <input name="subject" value={form.subject} onChange={update} placeholder="Enter email subject header..." />
          </div>

          <div className="form-group">
            <label>Additional Headers (JSON format)</label>
            <input name="headers" value={form.headers} onChange={update} placeholder='{"behavior_anomaly": "0.85"}' />
          </div>

          <div className="form-group">
            <label>Email HTML/Plain Body</label>
            <textarea name="body" rows="6" value={form.body} onChange={update} placeholder="Paste your email text or HTML content here..." />
          </div>

          <button className="btn-primary" onClick={analyze} disabled={loading}>
            {loading ? "Decrypting & Analyzing..." : "Run Aegis Threat Analyzer"}
          </button>
        </section>

        {/* Right Panel: Result displays */}
        <section className="panel">
          <h2>Analysis Output</h2>
          {!result && (
            <div style={{ display: "flex", flexDirection: "column", height: "100%", justifyContent: "center", alignItems: "center", minHeight: "350px", color: "var(--text-secondary)" }}>
              <div style={{ fontSize: "3rem", marginBottom: "16px" }}>📡</div>
              <p style={{ fontWeight: "600" }}>Awaiting threat inspection request</p>
              <p style={{ fontSize: "0.8rem", textAlign: "center", maxWidth: "250px", marginTop: "8px" }}>Select a template on the left and click analyze to start.</p>
            </div>
          )}

          {result && (
            <>
              {/* Verdict Header */}
              <div className="result-header">
                <div>
                  <span style={{ display: "block", fontSize: "0.75rem", textTransform: "uppercase", color: "var(--text-secondary)", fontWeight: "600" }}>System Verdict</span>
                  <div style={{ fontSize: "1.5rem", fontWeight: "700", fontFamily: "var(--font-title)" }}>
                    {result.verdict.replace("-", " ")}
                  </div>
                </div>
                <div className={`verdict-badge ${result.verdict.toLowerCase().replace("-", "_")}`}>
                  {result.verdict}
                </div>
              </div>

              <div className="result-summary-grid">
                <div className="summary-metric">
                  <span>Risk Score</span>
                  <strong>{riskScore.toFixed(0)}/100</strong>
                </div>
                <div className="summary-metric">
                  <span>Confidence</span>
                  <strong>{((Number(result.confidence ?? 0)) * 100).toFixed(0)}%</strong>
                </div>
              </div>

              {/* Score Circular Gauge */}
              <div className="gauge-container">
                {(() => {
                  const score = riskScore
                  const radius = 54
                  const circ = 2 * Math.PI * radius
                  const offset = circ - (score / 100) * circ
                  const verdictClass = result.verdict.toLowerCase().replace("-", "_")
                  return (
                    <>
                      <svg width="130" height="130" viewBox="0 0 130 130" className="gauge-svg">
                        <circle cx="65" cy="65" r={radius} className="gauge-bg" />
                        <circle
                          cx="65"
                          cy="65"
                          r={radius}
                          className={`gauge-fill ${verdictClass}`}
                          strokeDasharray={circ}
                          strokeDashoffset={offset}
                        />
                      </svg>
                      <div className="gauge-text">
                        <span className="gauge-number">{score.toFixed(0)}</span>
                        <span className="gauge-label">Risk Rating</span>
                      </div>
                    </>
                  )
                })()}
              </div>

              <div className="inline-signal-section">
                <h4>Signal Breakdown</h4>
                <SignalBreakdown signals={signalData} compact />
              </div>

              {/* Detail Tabs */}
              <div className="tabs-header">
                <button className={`tab-btn ${activeTab === "severity" ? "active" : ""}`} onClick={() => setActiveTab("severity")}>
                  Threat Factors
                </button>
                <button className={`tab-btn ${activeTab === "signals" ? "active" : ""}`} onClick={() => setActiveTab("signals")}>
                  Signal Breakdown
                </button>
                <button className={`tab-btn ${activeTab === "urls" ? "active" : ""}`} onClick={() => setActiveTab("urls")}>
                  URL Scan ({result.urls ? result.urls.length : 0})
                </button>
              </div>

              {/* Tab Contents */}
              <div className="tab-content">
                {activeTab === "severity" && (
                  <>
                    <h4 style={{ fontSize: "0.9rem", color: "var(--text-secondary)", fontWeight: "700" }}>Analysis Reasons:</h4>
                    <ul className="reasons-list">
                      {result.reasons.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>

                    <h4 style={{ fontSize: "0.9rem", color: "var(--text-secondary)", fontWeight: "700", marginTop: "10px" }}>Mitigation Controls:</h4>
                    <div className="actions-container">
                      {result.actions.map(action => (
                        <span key={action} className={`action-tag ${action.toLowerCase()}`}>
                          🛡️ {action.replace("_", " ")}
                        </span>
                      ))}
                    </div>
                  </>
                )}

                {activeTab === "signals" && (
                  <SignalBreakdown signals={signalData} />
                )}

                {activeTab === "urls" && (
                  <div className="url-scan-list">
                    {result.urls && result.urls.length > 0 ? (
                      result.urls.map((u, i) => {
                        let riskLevel = "clean"
                        if (u.risk >= 0.5) riskLevel = "danger"
                        else if (u.risk >= 0.2) riskLevel = "medium"
                        return (
                          <div key={i} className="url-card">
                            <div className="url-card-header">
                              <div className="url-text">{u.url}</div>
                              <span className={`url-risk-badge ${riskLevel}`}>
                                {(u.risk * 100).toFixed(0)}% Risk
                              </span>
                            </div>
                            {u.reasons && u.reasons.length > 0 && (
                              <div className="url-details-info">
                                <strong>Indicators:</strong>
                                <ul>
                                  {u.reasons.map((r, rIdx) => <li key={rIdx}>{r}</li>)}
                                </ul>
                              </div>
                            )}
                          </div>
                        )
                      })
                    ) : (
                      <div style={{ padding: "40px 0", textAlign: "center", color: "var(--text-secondary)", fontSize: "0.88rem" }}>
                        🔒 No URLs detected in the email body.
                      </div>
                    )}
                  </div>
                )}
              </div>
            </>
          )}
        </section>
      </main>

      {/* Footer / Incidents list */}
      <section className="panel incident-log">
        <h2>Recent Threats Inspected</h2>
        {alerts.length === 0 ? (
          <p style={{ textAlign: "center", color: "var(--text-secondary)", padding: "20px 0", fontSize: "0.88rem" }}>
            No emails have been inspected in this session. Use the tool above to start scanning.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Sender</th>
                <th>Subject</th>
                <th>System Verdict</th>
                <th>Risk Rating</th>
                <th style={{ textAlign: "right" }}>Operation</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map(row => {
                const verdictClass = row.verdict.toLowerCase().replace("-", "_")
                const riskRating = row.risk_score
                let riskClass = "low"
                if (riskRating >= 60) riskClass = "high"
                else if (riskRating >= 30) riskClass = "medium"

                return (
                  <tr key={row.id}>
                    <td className="log-sender">{row.sender}</td>
                    <td className="log-subject">{row.subject.length > 40 ? row.subject.substring(0, 40) + "..." : row.subject}</td>
                    <td>
                      <span className={`log-badge ${verdictClass}`}>{row.verdict}</span>
                    </td>
                    <td className={`log-risk ${riskClass}`}>{riskRating.toFixed(0)}/100</td>
                    <td style={{ textAlign: "right" }}>
                      <button className="btn-inspect" onClick={() => inspectIncident(row)}>
                        Inspect Report
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}

function SignalBreakdown({ signals = {}, compact = false }) {
  return (
    <div className={`signal-meters ${compact ? "compact" : ""}`}>
      <SignalMeter label="Language Semantics Model (NLP)" value={signals.nlp_score} />
      <SignalMeter label="Hyperlink Risk Profile" value={signals.url_score} />
      <SignalMeter label="Envelope / Header Anomaly" value={signals.header_score} />
      <SignalMeter label="Malicious Attachment Danger" value={signals.attachment_score} />
      <SignalMeter label="Sender Historical Behavior Anomaly" value={signals.sender_behavior_score} />
    </div>
  )
}

function SignalMeter({ label, value }) {
  const normalizedValue = Number(value ?? 0)
  const percent = Math.min(100, Math.max(0, normalizedValue * 100))
  return (
    <div className="signal-row">
      <div className="signal-label-wrapper">
        <span className="signal-name">{label}</span>
        <span className="signal-value">{percent.toFixed(0)}%</span>
      </div>
      <div className="meter-bg">
        <div
          className="meter-fill"
          style={{
            width: `${percent}%`,
            backgroundColor: normalizedValue >= 0.5 ? 'var(--color-phishing)' : normalizedValue >= 0.2 ? 'var(--color-suspicious)' : 'var(--color-safe)',
            boxShadow: normalizedValue >= 0.5 ? '0 0 6px var(--color-phishing)' : normalizedValue >= 0.2 ? '0 0 6px var(--color-suspicious)' : '0 0 6px var(--color-safe)'
          }}
        />
      </div>
    </div>
  )
}

createRoot(document.getElementById("root")).render(<App />)
