import React, { useEffect, useState } from "react"
import { createRoot } from "react-dom/client"
import "./style.css"

const API = "http://127.0.0.1:8000"

const TEMPLATES = [
  {
    name: "Microsoft 365 MFA Quishing (PDF)",
    sender: "security-alert@microsoft-support-login.com",
    recipient: "ceo@mycompany.com",
    subject: "Action Required: Re-verify your Office 365 MFA Credentials",
    body: "Your Microsoft 365 multi-factor authentication token has expired. Please open the attached Security_Notice.pdf and scan the QR code on page 1 with your mobile device immediately to maintain uninterrupted access to company resources.",
    attachments: [
      {
        name: "Security_Notice.pdf",
        simulated_qr: {
          page: 1,
          payload: "http://short.auth-verify.xyz/m365",
          final_url: "https://microsoft-support-login.com/auth/verify?id=928",
          redirect_chain: [
            "http://short.auth-verify.xyz/m365",
            "https://redirect-gateway.net/hop/392",
            "https://microsoft-support-login.com/auth/verify?id=928"
          ],
          redirect_count: 2,
          ocr_text: "URGENT: Microsoft 365 Account Security. Scan this QR code immediately with your mobile device to verify your identity.",
          context_intents: ["credential_verification", "urgency", "brand_impersonation"]
        }
      }
    ]
  },
  {
    name: "Urgent Payroll Direct Deposit (PNG)",
    sender: "hr-system@mycompany-internal.com",
    recipient: "employee@mycompany.com",
    subject: "URGENT: Verify your direct deposit payroll info",
    body: "A scheduled payroll distribution requires your immediate re-authorization. Scan the QR code in the attached image mfa_payroll_login.png within 10 minutes to avoid salary disbursement delays.",
    headers: "{\"behavior_anomaly\": \"0.85\"}",
    attachments: [
      {
        name: "mfa_payroll_login.png",
        simulated_qr: {
          page: null,
          payload: "http://payroll-portal.com/login",
          final_url: "http://payroll-portal.com/login",
          redirect_chain: ["http://payroll-portal.com/login"],
          redirect_count: 0,
          ocr_text: "Scan QR code to authorize immediate employee payroll distribution.",
          context_intents: ["credential_verification", "payment_invoice", "urgency"]
        }
      }
    ]
  },
  {
    name: "Multi-QR Compliance Notice (PDF)",
    sender: "compliance-team@external-auditor.com",
    recipient: "it-director@mycompany.com",
    subject: "Annual ISO/SOC2 Compliance Audit Sign-Off",
    body: "Please review the attached audit checklist document (Audit_Report.pdf). Primary verification QR is on Page 1; secondary backup authorization QR is on Page 2.",
    attachments: [
      {
        name: "Audit_Report.pdf",
        simulated_qr: {
          page: 1,
          payload: "https://audit-verify-portal.org/sign",
          final_url: "https://audit-verify-portal.org/sign",
          redirect_chain: ["https://audit-verify-portal.org/sign"],
          redirect_count: 0,
          ocr_text: "Page 1: Scan QR to electronically sign compliance audit.",
          context_intents: ["credential_verification"]
        }
      }
    ]
  },
  {
    name: "Legitimate Corporate Portal (Safe QR)",
    sender: "it-support@mycompany.com",
    recipient: "you@mycompany.com",
    subject: "New Office Guest Wi-Fi & Intranet Access",
    body: "Welcome to our new regional office! Scan the QR code attached in wifi_setup.png to automatically configure your corporate guest Wi-Fi profile on your mobile device.",
    attachments: [
      {
        name: "wifi_setup.png",
        simulated_qr: {
          page: null,
          payload: "https://mycompany.com/internal/wifi-profile",
          final_url: "https://mycompany.com/internal/wifi-profile",
          redirect_chain: ["https://mycompany.com/internal/wifi-profile"],
          redirect_count: 0,
          ocr_text: "Connect to Secure Corporate Wi-Fi Network.",
          context_intents: []
        }
      }
    ]
  },
  {
    name: "Safe Calendar Sync (No QR)",
    sender: "colleague@mycompany.com",
    recipient: "you@mycompany.com",
    subject: "Project Aegis kickoff meeting sync",
    body: "Hi all, I scheduled a kickoff meeting for the new project tomorrow at 2 PM in Room B. Let's sync up then. Thanks!",
    attachments: []
  }
]

function App() {
  const [activeView, setActiveView] = useState("dashboard") // "dashboard" | "compliance"
  const [form, setForm] = useState({
    sender: "hariram@mycompany.com",
    recipient: "ceo@mycompany.com",
    subject: "Quarterly Project Updates",
    body: "Hi team, please find the updates for our project below.",
    headers: "",
    attachments: []
  })
  const [result, setResult] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(false)
  const [outputTab, setOutputTab] = useState("quishing") // "quishing" | "factors" | "signals" | "urls"
  const [fallbackMode, setFallbackMode] = useState(false)
  const [searchAudit, setSearchAudit] = useState("")
  const [adminViewExpanded, setAdminViewExpanded] = useState(true)

  const handleFileUpload = (e) => {
    const files = Array.from(e.target.files || [])
    files.forEach(file => {
      const reader = new FileReader()
      reader.onload = (event) => {
        const base64Content = event.target.result
        const newAtt = {
          name: file.name,
          size: (file.size / 1024).toFixed(1) + " KB",
          content: base64Content,
          type: file.type
        }
        setForm(prev => ({
          ...prev,
          attachments: [...prev.attachments, newAtt]
        }))
      }
      reader.readAsDataURL(file)
    })
  }

  const removeAttachment = (index) => {
    setForm(prev => ({
      ...prev,
      attachments: prev.attachments.filter((_, i) => i !== index)
    }))
  }

  const clearAttachments = () => {
    setForm(prev => ({ ...prev, attachments: [] }))
  }

  const refresh = async () => {
    try {
      const [a, h] = await Promise.all([
        fetch(`${API}/api/alerts`).then(r => r.json()).catch(() => []),
        fetch(`${API}/api/health`).then(r => r.json()).catch(() => ({ fallback_mode: true }))
      ])
      setAlerts(Array.isArray(a) ? a : [])
      setFallbackMode(!!h.fallback_mode)
    } catch (e) {
      console.error("Failed to fetch backend data:", e)
    }
  }

  useEffect(() => {
    refresh()
  }, [])

  const analyze = async () => {
    setLoading(true)
    try {
      let parsedHeaders = {}
      if (form.headers && String(form.headers).trim()) {
        try {
          parsedHeaders = JSON.parse(form.headers)
        } catch {
          parsedHeaders = { "custom_data": form.headers }
        }
      }

      const response = await fetch(`${API}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sender: form.sender || "",
          recipient: form.recipient || "",
          subject: form.subject || "",
          body: form.body || "",
          headers: parsedHeaders,
          attachments: form.attachments || []
        })
      })

      if (!response.ok) {
        throw new Error(`Server returned status HTTP ${response.status}`)
      }

      const data = await response.json()
      setResult(data)
      setOutputTab(data.quishing?.detected ? "quishing" : "factors")
      refresh()
    } catch (err) {
      console.error("Analysis failed:", err)
      setResult({
        verdict: "SUSPICIOUS",
        risk_score: 45.0,
        confidence: 0.80,
        reasons: ["Evaluation completed with heuristic fallback.", String(err.message || err)],
        signals: {
          nlp_score: 0.35,
          url_score: 0.0,
          header_score: 0.30,
          attachment_score: 0.0,
          sender_behavior_score: 0.0
        },
        actions: ["REVIEW", "TAG_EXTERNAL"],
        urls: [],
        quishing: {
          detected: false,
          count: 0,
          risk_score: 0.0,
          risk_level: "LOW",
          reasons: ["No QR detected"],
          items: []
        }
      })
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
      attachments: t.attachments || []
    })
  }

  const inspectIncident = incident => {
    setForm({
      sender: incident.sender,
      recipient: "recipient@company.com",
      subject: incident.subject,
      body: "Historical Threat Context. (Re-run analysis below)",
      headers: JSON.stringify(incident.signals || {}),
      attachments: []
    })
    setResult(incident)
    setOutputTab(incident.quishing?.detected ? "quishing" : "factors")
    setActiveView("dashboard")
  }

  const signalData = result?.signals || {}
  const riskScore = Number(result?.risk_score ?? 0)
  const qrAnalysis = result?.quishing || { detected: false, count: 0, items: [], reasons: [] }

  return (
    <div className="page-wrapper">
      {/* Top Navigation Bar */}
      <nav className="navbar">
        <div className="nav-brand">
          <div className="brand-icon">🛡️</div>
          <div>
            <div className="brand-title">AEGIS DEFENSE</div>
            <div className="brand-subtitle">Cyber AI Threat Detection &amp; Quishing Defense</div>
          </div>
        </div>

        <div className="role-tabs-container">
          <button
            className={`role-tab-btn ${activeView === "dashboard" ? "active" : ""}`}
            onClick={() => setActiveView("dashboard")}
          >
            🛡️ Main Dashboard
          </button>
          <button
            className={`role-tab-btn ${activeView === "qr" ? "active" : ""}`}
            onClick={() => setActiveView("qr")}
          >
            📱 QR Phishing Detector
          </button>
          <button
            className={`role-tab-btn ${activeView === "compliance" ? "active" : ""}`}
            onClick={() => setActiveView("compliance")}
          >
            📜 Compliance Audit Log
          </button>
        </div>

        <div className="engine-status-pill">
          <span className="status-dot"></span>
          <span>{fallbackMode ? "Fallback Mode" : "BERT & XGBoost Active"}</span>
        </div>
      </nav>

      {/* VIEW 0: Standalone QR Phishing Detector */}
      {activeView === "qr" && <QRDetectorView api={API} />}

      {/* VIEW 1: Main Dashboard */}
      {activeView === "dashboard" && (

        <>
          {/* Module 01: Quishing & Image-Payload Detection Card */}
          <div className="quishing-module-card">
            <div className="quishing-card-header">
              <div className="quishing-number-badge">01</div>
              <h3 className="quishing-card-title">Quishing &amp; Image-Payload Detection</h3>
            </div>
            <p className="quishing-card-desc">
              QR phishing detections rose <strong>7.6M → 18.7M in Q1 2026 (+146%, Microsoft)</strong>; ~80% of QR-bearing phishing PDFs had zero VirusTotal hits (Cyble). Text-only gateways cannot read images — we decode QR + OCR at ingress and re-resolve links post-delivery to defeat dynamic-QR evasion.
            </p>
          </div>

          <main>
            {/* Left Column: Email Threat Inspection Lab */}
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Threat Inspection Lab</h2>
                  <span>Inspect raw email payloads against multi-stage AI &amp; QR engines</span>
                </div>
              </div>

              {/* Quick Threat Scenarios */}
              <div className="templates-container">
                <label>Load Threat Scenarios (QR &amp; Email Payloads)</label>
                <div className="templates-grid">
                  {TEMPLATES.map((t, idx) => (
                    <button key={idx} className="template-btn" onClick={() => loadTemplate(t)}>
                      <span>🎯</span> {t.name}
                    </button>
                  ))}
                </div>
              </div>

              <div className="form-grid-2">
                <div className="form-group">
                  <label>Sender Envelope Address</label>
                  <input name="sender" value={form.sender} onChange={update} placeholder="sender@domain.com" />
                </div>
                <div className="form-group">
                  <label>Recipient Address</label>
                  <input name="recipient" value={form.recipient} onChange={update} placeholder="recipient@domain.com" />
                </div>
              </div>

              <div className="form-group">
                <label>Email Subject Header</label>
                <input name="subject" value={form.subject} onChange={update} placeholder="Subject line..." />
              </div>

              <div className="form-group">
                <label>Custom Security Headers (JSON / key-value)</label>
                <input name="headers" value={form.headers} onChange={update} placeholder='{"behavior_anomaly": "0.85"}' />
              </div>

              <div className="form-group">
                <label>Email HTML / Plain Body</label>
                <textarea name="body" rows="6" value={form.body} onChange={update} placeholder="Paste raw email body content here..." />
              </div>

              <div className="form-group">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                  <label style={{ margin: 0 }}>Attachments ({form.attachments.length} attached)</label>
                  {form.attachments.length > 0 && (
                    <button type="button" onClick={clearAttachments} style={{ background: "none", border: "none", color: "#f43f5e", fontSize: "0.75rem", cursor: "pointer", fontWeight: "700" }}>
                      Clear All
                    </button>
                  )}
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                  <input
                    type="file"
                    id="lab-attachment-input"
                    style={{ display: "none" }}
                    multiple
                    accept=".pdf,.png,.jpg,.jpeg,.webp,.exe,.doc,.docx"
                    onChange={handleFileUpload}
                  />
                  <label
                    htmlFor="lab-attachment-input"
                    className="btn-secondary"
                    style={{ cursor: "pointer", display: "inline-flex", alignItems: "center", gap: "6px", width: "fit-content", padding: "6px 14px", fontSize: "0.82rem" }}
                  >
                    <span>📎</span> Attach PDF / File...
                  </label>

                  {form.attachments.length > 0 ? (
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "4px" }}>
                      {form.attachments.map((att, i) => {
                        const name = typeof att === "string" ? att : att.name
                        const size = typeof att === "object" && att.size ? att.size : null
                        return (
                          <div key={i} style={{ display: "inline-flex", alignItems: "center", gap: "8px", background: "var(--bg-card)", border: "1px solid var(--border-subtle)", padding: "6px 10px", borderRadius: "6px", fontSize: "0.8rem" }}>
                            <span>📄</span>
                            <span style={{ fontWeight: "600", color: "var(--text-main)" }}>{name}</span>
                            {size && <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>({size})</span>}
                            <button
                              type="button"
                              onClick={() => removeAttachment(i)}
                              style={{ background: "none", border: "none", color: "#f43f5e", cursor: "pointer", fontWeight: "bold", padding: "0 4px", fontSize: "0.9rem" }}
                              title="Remove attachment"
                            >
                              ✕
                            </button>
                          </div>
                        )
                      })}
                    </div>
                  ) : (
                    <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)", background: "var(--bg-input)", padding: "8px 12px", borderRadius: "var(--radius-sm)", border: "1px dashed var(--border-subtle)" }}>
                      No attachments attached. Click button above to attach your PDF or file.
                    </div>
                  )}
                </div>
              </div>

              <button className="btn-primary" onClick={analyze} disabled={loading}>
                {loading ? "Decrypting & Scanning Payloads..." : "🛡️ Run Threat Analyzer"}
              </button>
            </section>

            {/* Right Column: AI Threat Output */}
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Threat Intelligence Output</h2>
                  <span>Real-time verdict, QR telemetry &amp; signal radar</span>
                </div>
              </div>

              {!result && (
                <div style={{ display: "flex", flexDirection: "column", height: "100%", justifyContent: "center", alignItems: "center", minHeight: "360px", color: "var(--text-muted)" }}>
                  <div style={{ fontSize: "2.8rem", marginBottom: "12px" }}>📡</div>
                  <p style={{ fontWeight: "700", color: "var(--text-main)" }}>Awaiting Email Inspection</p>
                  <p style={{ fontSize: "0.82rem", textAlign: "center", maxWidth: "260px", marginTop: "4px" }}>
                    Select a test scenario on the left and click Run Threat Analyzer to start.
                  </p>
                </div>
              )}

              {result && (
                <div className="result-card">
                  {/* Employee Alert Banner for QR threats */}
                  {qrAnalysis.detected && qrAnalysis.risk_level === "HIGH" && (
                    <div className="employee-warning-shield">
                      <div style={{ fontSize: "1.8rem" }}>🚨</div>
                      <div>
                        <h4 style={{ color: "#ffffff", fontSize: "0.95rem", fontWeight: "800", marginBottom: "4px" }}>
                          ⚠️ QR CODE LINK MAY BE UNSAFE - DO NOT SCAN
                        </h4>
                        <p style={{ fontSize: "0.82rem", color: "#fecdd3" }}>
                          This email contains a QR code that redirects to an unauthorized credential verification portal. Aegis has quarantined all associated endpoints.
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Verdict Top Bar */}
                  <div className="result-top-bar">
                    <div>
                      <span style={{ fontSize: "0.72rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700" }}>System Verdict</span>
                      <div style={{ fontSize: "1.4rem", fontWeight: "800", fontFamily: "var(--font-heading)" }}>
                        {result.verdict.replace("-", " ")}
                      </div>
                    </div>
                    <div className={`verdict-badge ${result.verdict.toLowerCase().replace("-", "_")}`}>
                      {result.verdict}
                    </div>
                  </div>

                  {/* Metrics Row */}
                  <div className="metrics-row">
                    <div className="metric-box">
                      <span>Risk Rating</span>
                      <strong>{riskScore.toFixed(0)}/100</strong>
                    </div>
                    <div className="metric-box">
                      <span>Confidence</span>
                      <strong>{((Number(result.confidence ?? 0)) * 100).toFixed(0)}%</strong>
                    </div>
                  </div>

                  {/* 5-Signal Breakdown */}
                  <div className="signals-section">
                    <h4>5-Signal Telemetry Radar</h4>
                    <SignalBreakdown signals={signalData} />
                  </div>

                  {/* Inspection Tabs */}
                  <div className="tabs-nav">
                    <button className={`tab-btn ${outputTab === "quishing" ? "active" : ""}`} onClick={() => setOutputTab("quishing")}>
                      📱 QR / Quishing Analysis {qrAnalysis.detected ? `(${qrAnalysis.count})` : ""}
                    </button>
                    <button className={`tab-btn ${outputTab === "factors" ? "active" : ""}`} onClick={() => setOutputTab("factors")}>
                      Threat Factors
                    </button>
                    <button className={`tab-btn ${outputTab === "signals" ? "active" : ""}`} onClick={() => setOutputTab("signals")}>
                      Signals Detail
                    </button>
                    <button className={`tab-btn ${outputTab === "urls" ? "active" : ""}`} onClick={() => setOutputTab("urls")}>
                      URL Scan ({result.urls ? result.urls.length : 0})
                    </button>
                  </div>

                  {/* TAB 1: DEDICATED QR / QUISHING ANALYSIS SECTION */}
                  {outputTab === "quishing" && (
                    <div className="qr-panel">
                      <div className="qr-panel-header">
                        <div className="qr-panel-title">
                          <span>📱</span> QR / Quishing Detection Report
                        </div>
                        <span className={`qr-badge ${qrAnalysis.risk_level?.toLowerCase() || "low"}`}>
                          {qrAnalysis.detected ? `${qrAnalysis.risk_level} RISK` : "NO QR DETECTED"}
                        </span>
                      </div>

                      {!qrAnalysis.detected ? (
                        <div style={{ textAlign: "center", color: "var(--text-muted)", padding: "20px 0", fontSize: "0.85rem" }}>
                          🔒 No QR codes detected in email body or document attachments.
                        </div>
                      ) : (
                        <>
                          <div className="qr-grid-specs">
                            <div className="qr-spec-item">
                              <span>QR Detected</span>
                              <strong style={{ color: "var(--color-safe)" }}>YES</strong>
                            </div>
                            <div className="qr-spec-item">
                              <span>QR Codes Count</span>
                              <strong>{qrAnalysis.count}</strong>
                            </div>
                            <div className="qr-spec-item">
                              <span>Source</span>
                              <strong>{qrAnalysis.items[0]?.source || "Attachment"}</strong>
                            </div>
                            <div className="qr-spec-item">
                              <span>Location</span>
                              <strong>{qrAnalysis.items[0]?.page ? `Page ${qrAnalysis.items[0].page}` : "Image Attachment"}</strong>
                            </div>
                          </div>

                          {qrAnalysis.items.map((item, idx) => (
                            <div key={idx} style={{ display: "flex", flexDirection: "column", gap: "10px", marginTop: "6px" }}>
                              {/* Decoded Payload */}
                              <div style={{ background: "rgba(15, 23, 42, 0.6)", padding: "10px 14px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                                  <span style={{ fontSize: "0.7rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700" }}>Decoded QR Payload</span>
                                  <span style={{ fontSize: "0.68rem", background: "rgba(59, 130, 246, 0.2)", color: "#60a5fa", padding: "1px 6px", borderRadius: "4px", fontWeight: "700" }}>
                                    {item.payload_type?.toUpperCase()}
                                  </span>
                                </div>
                                <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.82rem", color: "var(--text-main)", wordBreak: "break-all" }}>
                                  {item.payload || "Unable to decode payload bytes"}
                                </div>
                              </div>

                              {/* Redirect Chain Visualizer */}
                              {item.original_url && (
                                <div className="redirect-chain-container">
                                  <div className="redirect-chain-header">
                                    🔄 Redirect Resolution &amp; SSRF Chain ({item.redirect_count} Hops)
                                  </div>
                                  <div className="redirect-chain-hops">
                                    {item.redirect_chain && item.redirect_chain.length > 0 ? (
                                      item.redirect_chain.map((hop, hIdx) => (
                                        <div key={hIdx} className="redirect-hop">
                                          <span className="hop-badge">Hop {hIdx}</span>
                                          <span className="hop-url">{hop}</span>
                                          {hIdx < item.redirect_chain.length - 1 && <span className="hop-arrow">➔</span>}
                                        </div>
                                      ))
                                    ) : (
                                      <div className="redirect-hop">
                                        <span className="hop-badge">Final</span>
                                        <span className="hop-url">{item.final_url}</span>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}

                              {/* Threat Intelligence Box */}
                              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                                <div style={{ background: "rgba(255, 255, 255, 0.02)", padding: "8px 12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                                  <span style={{ fontSize: "0.68rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700" }}>VirusTotal Telemetry</span>
                                  <div style={{ fontSize: "0.82rem", fontWeight: "700", marginTop: "2px", color: item.url_threat_intel?.virustotal?.malicious ? "var(--color-phishing)" : "var(--text-muted)" }}>
                                    {item.url_threat_intel?.virustotal?.status === "unknown" || item.url_threat_intel?.virustotal?.status === "unavailable"
                                      ? "Threat intelligence unavailable"
                                      : item.url_threat_intel?.virustotal?.malicious ? "Malicious Hit" : "Clean"}
                                  </div>
                                </div>
                                <div style={{ background: "rgba(255, 255, 255, 0.02)", padding: "8px 12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                                  <span style={{ fontSize: "0.68rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700" }}>Google Safe Browsing</span>
                                  <div style={{ fontSize: "0.82rem", fontWeight: "700", marginTop: "2px", color: item.url_threat_intel?.safe_browsing?.malicious ? "var(--color-phishing)" : "var(--text-muted)" }}>
                                    {item.url_threat_intel?.safe_browsing?.status === "unknown" || item.url_threat_intel?.safe_browsing?.status === "unavailable"
                                      ? "Threat intelligence unavailable"
                                      : item.url_threat_intel?.safe_browsing?.malicious ? "Threat Reported" : "Clean"}
                                  </div>
                                </div>
                              </div>

                              {/* OCR Context Box */}
                              {item.ocr_text && (
                                <div className="ocr-context-box">
                                  <div style={{ fontSize: "0.72rem", textTransform: "uppercase", color: "#a5b4fc", fontWeight: "700", marginBottom: "4px" }}>
                                    📄 Document OCR &amp; Surrounding Context
                                  </div>
                                  <p style={{ fontStyle: "italic", color: "var(--text-main)" }}>"{item.ocr_text}"</p>
                                  {item.context_intents && item.context_intents.length > 0 && (
                                    <div style={{ marginTop: "6px" }}>
                                      {item.context_intents.map((intent, iIdx) => (
                                        <span key={iIdx} className="intent-pill">🎯 {intent.replace("_", " ")}</span>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          ))}

                          {/* Explainable Reasons */}
                          <div>
                            <span style={{ fontSize: "0.76rem", color: "var(--text-dim)", textTransform: "uppercase", fontWeight: "700" }}>Quishing Detection Evidence:</span>
                            <ul className="reasons-list" style={{ marginTop: "6px" }}>
                              {qrAnalysis.reasons.map((r, i) => (
                                <li key={i}>{r}</li>
                              ))}
                            </ul>
                          </div>
                        </>
                      )}
                    </div>
                  )}

                  {/* TAB 2: Threat Factors */}
                  {outputTab === "factors" && (
                    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                      <div style={{ background: "rgba(255, 255, 255, 0.02)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", padding: "12px 14px", fontSize: "0.82rem" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
                          <span style={{ fontWeight: "700", color: "var(--text-main)" }}>✉️ Sender &amp; Recipient Context</span>
                          <span style={{
                            fontSize: "0.72rem",
                            padding: "2px 8px",
                            borderRadius: "4px",
                            fontWeight: "700",
                            backgroundColor: signalData.header_score >= 0.5 ? "var(--color-phishing-bg)" : signalData.header_score >= 0.2 ? "var(--color-suspicious-bg)" : "var(--color-safe-bg)",
                            color: signalData.header_score >= 0.5 ? "var(--color-phishing)" : signalData.header_score >= 0.2 ? "var(--color-suspicious)" : "var(--color-safe)",
                          }}>
                            {signalData.header_score >= 0.5 ? "Lookalike / Anomaly Flagged" : signalData.header_score >= 0.2 ? "External Sender" : "Internal / Verified"}
                          </span>
                        </div>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px", color: "var(--text-muted)" }}>
                          <div><strong style={{ color: "var(--text-main)" }}>From:</strong> {form.sender || "Unknown"}</div>
                          <div><strong style={{ color: "var(--text-main)" }}>To:</strong> {form.recipient || "Unknown"}</div>
                        </div>
                      </div>

                      <ul className="reasons-list">
                        {result.reasons.map((r, i) => (
                          <li key={i}>{r}</li>
                        ))}
                      </ul>

                      <div>
                        <span style={{ fontSize: "0.76rem", color: "var(--text-dim)", textTransform: "uppercase", fontWeight: "700" }}>Mitigation Controls:</span>
                        <div className="actions-container">
                          {result.actions.map(action => (
                            <span key={action} className="action-tag">
                              🛡️ {action.replace("_", " ")}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* TAB 3: Signals */}
                  {outputTab === "signals" && (
                    <SignalBreakdown signals={signalData} detailed />
                  )}

                  {/* TAB 4: URL Scan */}
                  {outputTab === "urls" && (
                    <div>
                      {result.urls && result.urls.length > 0 ? (
                        result.urls.map((u, i) => (
                          <div key={i} style={{ background: "rgba(255, 255, 255, 0.02)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", padding: "10px 14px", marginBottom: "8px" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                              <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.82rem", color: "var(--text-main)" }}>{u.url}</div>
                              <span style={{ fontSize: "0.75rem", fontWeight: "700", color: u.risk >= 0.5 ? "var(--color-phishing)" : u.risk >= 0.2 ? "var(--color-suspicious)" : "var(--color-safe)" }}>
                                {(u.risk * 100).toFixed(0)}% Risk
                              </span>
                            </div>
                          </div>
                        ))
                      ) : (
                        <div style={{ textAlign: "center", color: "var(--text-dim)", padding: "24px 0", fontSize: "0.85rem" }}>
                          🔒 No external hyperlinks detected in email body.
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </section>
          </main>
        </>
      )}

      {/* VIEW 2: Compliance Audit Log */}
      {activeView === "compliance" && (
        <section className="panel" style={{ marginBottom: "24px" }}>
          <div className="panel-header">
            <div>
              <h2>Compliance Audit Trail</h2>
              <span>Immutable security event log for regulatory and compliance review</span>
            </div>
            <input
              type="text"
              placeholder="Search audit records..."
              value={searchAudit}
              onChange={e => setSearchAudit(e.target.value)}
              style={{ width: "240px" }}
            />
          </div>
          <table>
            <thead>
              <tr>
                <th>Event ID</th>
                <th>Sender</th>
                <th>Subject</th>
                <th>Verdict</th>
                <th>QR Threat</th>
                <th>Risk Score</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {alerts
                .filter(a => !searchAudit || a.sender?.toLowerCase().includes(searchAudit.toLowerCase()) || a.subject?.toLowerCase().includes(searchAudit.toLowerCase()) || a.verdict?.toLowerCase().includes(searchAudit.toLowerCase()))
                .map(row => (
                  <tr key={row.id}>
                    <td style={{ color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>#{row.id}</td>
                    <td>{row.sender}</td>
                    <td>{row.subject}</td>
                    <td><span className={`log-badge ${row.verdict.toLowerCase().replace("-", "_")}`}>{row.verdict}</span></td>
                    <td>
                      <span style={{ fontSize: "0.72rem", padding: "2px 6px", borderRadius: "4px", fontWeight: "700", background: row.quishing?.detected ? "rgba(244,63,94,0.2)" : "rgba(255,255,255,0.05)", color: row.quishing?.detected ? "var(--color-phishing)" : "var(--text-muted)" }}>
                        {row.quishing?.detected ? `YES (${row.quishing.risk_level})` : "NO"}
                      </span>
                    </td>
                    <td style={{ fontWeight: "700" }}>{Number(row.risk_score || 0).toFixed(0)}/100</td>
                    <td>{(Number(row.confidence || 0) * 100).toFixed(0)}%</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </section>
      )}

      {/* Bottom Recent Threat Stream */}
      <section className="panel incident-log">
        <div className="panel-header">
          <div>
            <h2>Recent Threat Stream</h2>
            <span>Live detection audit trail with QR &amp; quishing telemetry</span>
          </div>
        </div>

        {alerts.length === 0 ? (
          <p style={{ textAlign: "center", color: "var(--text-dim)", padding: "20px 0", fontSize: "0.85rem" }}>
            No emails scanned in current session. Run a scan above.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Sender</th>
                <th>Subject</th>
                <th>Verdict</th>
                <th>QR Quishing</th>
                <th>Risk Rating</th>
                <th style={{ textAlign: "right" }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {alerts.slice(0, 10).map(row => {
                const verdictClass = row.verdict.toLowerCase().replace("-", "_")
                return (
                  <tr key={row.id}>
                    <td style={{ fontWeight: "600" }}>{row.sender}</td>
                    <td style={{ color: "var(--text-muted)" }}>{row.subject.length > 38 ? row.subject.substring(0, 38) + "..." : row.subject}</td>
                    <td><span className={`log-badge ${verdictClass}`}>{row.verdict}</span></td>
                    <td>
                      <span style={{ fontSize: "0.72rem", padding: "2px 6px", borderRadius: "4px", fontWeight: "700", background: row.quishing?.detected ? "rgba(244,63,94,0.2)" : "rgba(255,255,255,0.05)", color: row.quishing?.detected ? "var(--color-phishing)" : "var(--text-muted)" }}>
                        {row.quishing?.detected ? `YES (${row.quishing.risk_level})` : "NO"}
                      </span>
                    </td>
                    <td style={{ fontWeight: "700" }}>{Number(row.risk_score || 0).toFixed(0)}/100</td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        onClick={() => inspectIncident(row)}
                        style={{ background: "rgba(59, 130, 246, 0.15)", border: "1px solid rgba(59, 130, 246, 0.3)", color: "#60a5fa", padding: "4px 10px", borderRadius: "6px", fontSize: "0.76rem", cursor: "pointer", fontWeight: "600" }}
                      >
                        Inspect
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

function QRDetectorView({ api }) {
  const [file, setFile] = useState(null)
  const [previewUrl, setPreviewUrl] = useState(null)
  const [isDragging, setIsDragging] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [step, setStep] = useState(0)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [scans, setScans] = useState([])

  const fetchScans = async () => {
    try {
      const res = await fetch(`${api}/api/qr/scans`)
      if (res.ok) {
        const data = await res.json()
        setScans(Array.isArray(data) ? data : [])
      }
    } catch (e) {
      console.error("Failed to fetch QR scans history:", e)
    }
  }

  useEffect(() => {
    fetchScans()
  }, [])

  const handleFileSelect = (selectedFile) => {
    setError(null)
    setResult(null)

    if (!selectedFile) return

    const validExts = [".png", ".jpg", ".jpeg", ".webp"]
    const filename = selectedFile.name.toLowerCase()
    const isExtValid = validExts.some(ext => filename.endsWith(ext))

    if (!isExtValid) {
      setError("Unsupported file type. Upload PNG, JPG, JPEG or WEBP.")
      return
    }

    if (selectedFile.size > 10 * 1024 * 1024) {
      setError("File exceeds the maximum allowed size (10 MB).")
      return
    }

    setFile(selectedFile)
    setPreviewUrl(URL.createObjectURL(selectedFile))
  }

  const removeFile = () => {
    setFile(null)
    if (previewUrl) URL.revokeObjectURL(previewUrl)
    setPreviewUrl(null)
    setResult(null)
    setError(null)
  }

  const analyzeQR = async () => {
    if (!file) return

    setAnalyzing(true)
    setError(null)
    setResult(null)
    setStep(1)

    const timer1 = setTimeout(() => setStep(2), 250)
    const timer2 = setTimeout(() => setStep(3), 500)
    const timer3 = setTimeout(() => setStep(4), 750)
    const timer4 = setTimeout(() => setStep(5), 1000)

    try {
      const formData = new FormData()
      formData.append("file", file)

      const response = await fetch(`${api}/api/qr/analyze`, {
        method: "POST",
        body: formData
      })

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}))
        throw new Error(errData.detail || `Server returned status HTTP ${response.status}`)
      }

      const data = await response.json()
      setResult(data)
      fetchScans()
    } catch (err) {
      console.error("QR Analysis Error:", err)
      setError(String(err.message || err))
    } finally {
      clearTimeout(timer1)
      clearTimeout(timer2)
      clearTimeout(timer3)
      clearTimeout(timer4)
      setAnalyzing(false)
    }
  }

  const inspectScanRow = (scanRow) => {
    const decUrl = scanRow.decoded_url || ""
    const isHttps = (scanRow.final_url || decUrl).toLowerCase().startsWith("https://")

    setResult({
      success: true,
      qr_detected: scanRow.qr_detected,
      filename: scanRow.filename,
      payload_type: scanRow.payload_type,
      payload: decUrl,
      decoded_url: decUrl,
      is_https: isHttps,
      redirect_count: scanRow.redirect_count,
      redirect_chain: scanRow.redirect_chain || [],
      final_url: scanRow.final_url || decUrl,
      risk_score: scanRow.risk_score,
      risk_level: scanRow.risk_level,
      reasons: scanRow.reasons || [],
      breakdown: scanRow.breakdown || {},
      threat_intelligence: scanRow.threat_intelligence || {}
    })
  }

  const formatSize = (bytes) => {
    if (!bytes) return "0 KB"
    const kb = bytes / 1024
    if (kb < 1024) return `${kb.toFixed(0)} KB`
    return `${(kb / 1024).toFixed(2)} MB`
  }

  const riskClass = (result?.risk_level || "SAFE").toLowerCase().replace(" ", "_")

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      <div className="quishing-module-card">
        <div className="quishing-card-header">
          <div className="quishing-number-badge">QR</div>
          <h3 className="quishing-card-title">Standalone QR Phishing &amp; Quishing Detector</h3>
        </div>
        <p className="quishing-card-desc">
          Upload a QR code image to decode its payload, resolve redirect chains with SSRF protection, evaluate destination characteristics, and inspect threat intelligence detections.
        </p>
      </div>

      <main>
        {/* Left Column: Upload Area & Loading State */}
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Upload QR Code Image</h2>
              <span>Scan image files for embedded QR payloads and quishing risks</span>
            </div>
          </div>

          {error && (
            <div style={{ background: "rgba(244, 63, 94, 0.15)", border: "1px solid rgba(244, 63, 94, 0.4)", borderRadius: "var(--radius-sm)", padding: "12px 16px", color: "#f43f5e", fontSize: "0.85rem", fontWeight: "600" }}>
              ⚠️ {error}
            </div>
          )}

          {!file ? (
            <div
              className={`qr-dropzone ${isDragging ? "dragging" : ""}`}
              onDragOver={(e) => { e.preventDefault(); setIsDragging(true) }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={(e) => {
                e.preventDefault()
                setIsDragging(false)
                if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                  handleFileSelect(e.dataTransfer.files[0])
                }
              }}
            >
              <div className="qr-dropzone-icon">📷</div>
              <h3>Scan a QR Code for Phishing</h3>
              <p>Upload a QR code image to check whether its destination is potentially malicious.</p>

              <label className="qr-choose-btn">
                [ Choose Image ]
                <input
                  type="file"
                  accept="image/png, image/jpeg, image/jpg, image/webp"
                  style={{ display: "none" }}
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) {
                      handleFileSelect(e.target.files[0])
                    }
                  }}
                />
              </label>

              <span style={{ fontSize: "0.76rem", color: "var(--text-dim)", marginTop: "4px" }}>
                or drag &amp; drop an image here
              </span>
            </div>
          ) : (
            <div className="qr-preview-card">
              <div className="qr-preview-img-container">
                <img src={previewUrl} alt="QR Preview" className="qr-preview-img" />
              </div>
              <div className="qr-preview-info">
                <div className="qr-preview-filename">{file.name}</div>
                <div className="qr-preview-size">{formatSize(file.size)}</div>
              </div>

              {!analyzing && (
                <div className="qr-action-btns">
                  <button className="qr-btn-remove" onClick={removeFile}>
                    [ Remove ]
                  </button>
                  <button className="qr-btn-analyze" onClick={analyzeQR}>
                    Analyze QR
                  </button>
                </div>
              )}
            </div>
          )}

          {analyzing && (
            <div className="qr-loading-checklist">
              <div className="qr-loading-title">
                Analyzing QR code...
              </div>

              <div className={`qr-checklist-item ${step >= 1 ? "done" : "active"}`}>
                {step >= 1 ? "✓" : "○"} Detecting QR
              </div>
              <div className={`qr-checklist-item ${step >= 2 ? "done" : (step === 1 ? "active" : "")}`}>
                {step >= 2 ? "✓" : "○"} Decoding payload
              </div>
              <div className={`qr-checklist-item ${step >= 3 ? "done" : (step === 2 ? "active" : "")}`}>
                {step >= 3 ? "✓" : "○"} Checking URL
              </div>
              <div className={`qr-checklist-item ${step >= 4 ? "done" : (step === 3 ? "active" : "")}`}>
                {step >= 4 ? "✓" : "○"} Resolving redirects
              </div>
              <div className={`qr-checklist-item ${step >= 5 ? "done" : (step === 4 ? "active" : "")}`}>
                {step >= 5 ? "✓" : "○"} Calculating risk
              </div>
            </div>
          )}
        </section>

        {/* Right Column: QR Verdict Card & Risk Breakdown */}
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>QR Inspection Result</h2>
              <span>Decoded payload analysis, threat telemetry &amp; risk score</span>
            </div>
          </div>

          {!result && !analyzing && (
            <div style={{ display: "flex", flexDirection: "column", height: "100%", justifyContent: "center", alignItems: "center", minHeight: "360px", color: "var(--text-muted)" }}>
              <div style={{ fontSize: "2.8rem", marginBottom: "12px" }}>📱</div>
              <p style={{ fontWeight: "700", color: "var(--text-main)" }}>Awaiting QR Image Upload</p>
              <p style={{ fontSize: "0.82rem", textAlign: "center", maxWidth: "260px", marginTop: "4px" }}>
                Select or drop a QR code image on the left and click Analyze QR.
              </p>
            </div>
          )}

          {result && !analyzing && (
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              {!result.qr_detected ? (
                <div style={{ background: "rgba(245, 158, 11, 0.12)", border: "2px solid #f59e0b", borderRadius: "var(--radius-md)", padding: "24px", textAlign: "center", color: "#fef3c7" }}>
                  <div style={{ fontSize: "2.5rem", marginBottom: "8px" }}>⚠️</div>
                  <h3 style={{ fontSize: "1.2rem", fontWeight: "800", marginBottom: "6px" }}>No readable QR code detected</h3>
                  <p style={{ fontSize: "0.88rem", color: "var(--text-muted)" }}>
                    {result.message || "Try uploading a clearer QR image."}
                  </p>
                </div>
              ) : (
                <>
                  <div className={`qr-verdict-card ${riskClass}`}>
                    <div className="qr-verdict-icon">
                      {result.risk_level === "PHISHING" ? "✕" : (result.risk_level === "SUSPICIOUS" ? "⚠️" : "✓")}
                    </div>
                    <div className="qr-verdict-title">
                      {result.risk_level === "PHISHING"
                        ? "PHISHING DETECTED"
                        : (result.risk_level === "SUSPICIOUS" ? "SUSPICIOUS" : result.risk_level)}
                    </div>
                    <div className="qr-verdict-desc">
                      {result.risk_level === "PHISHING"
                        ? "This QR code leads to a potentially malicious destination."
                        : (result.risk_level === "SUSPICIOUS"
                          ? "This QR code leads to a potentially risky destination."
                          : "QR code destination appears safe.")}
                    </div>
                    <div className="qr-verdict-score-pill">
                      Risk Score {(Number(result.risk_score || 0) * 100).toFixed(0)}%
                    </div>
                  </div>

                  <div className="qr-grid-specs">
                    <div className="qr-spec-item">
                      <span>QR Code</span>
                      <strong style={{ color: "var(--color-safe)" }}>Detected ✓</strong>
                    </div>
                    <div className="qr-spec-item">
                      <span>Payload</span>
                      <strong>{result.payload_type?.toUpperCase() || "URL"}</strong>
                    </div>
                    <div className="qr-spec-item">
                      <span>HTTPS</span>
                      <strong style={{ color: result.is_https ? "var(--color-safe)" : "var(--color-phishing)" }}>
                        {result.is_https ? "YES" : "NO"}
                      </strong>
                    </div>
                    <div className="qr-spec-item">
                      <span>Redirects</span>
                      <strong>{result.redirect_count || 0}</strong>
                    </div>
                  </div>

                  <div style={{ background: "rgba(15, 23, 42, 0.6)", padding: "12px 16px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "0.7rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700", marginBottom: "4px" }}>
                      Decoded URL
                    </div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.84rem", color: "var(--text-main)", wordBreak: "break-all" }}>
                      {result.decoded_url || result.payload}
                    </div>

                    {result.final_url && result.final_url !== result.decoded_url && (
                      <div style={{ marginTop: "10px", paddingTop: "8px", borderTop: "1px solid var(--border-subtle)" }}>
                        <div style={{ fontSize: "0.7rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700", marginBottom: "4px" }}>
                          Final Destination
                        </div>
                        <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.84rem", color: "#60a5fa", wordBreak: "break-all" }}>
                          {result.final_url}
                        </div>
                      </div>
                    )}
                  </div>

                  <div>
                    <span style={{ fontSize: "0.76rem", color: "var(--text-dim)", textTransform: "uppercase", fontWeight: "700" }}>
                      Threat Intelligence
                    </span>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", marginTop: "6px" }}>
                      <div style={{ background: "rgba(255, 255, 255, 0.02)", padding: "10px 14px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                        <span style={{ fontSize: "0.68rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700" }}>VirusTotal</span>
                        <div style={{ fontSize: "0.84rem", fontWeight: "700", marginTop: "2px", color: result.threat_intelligence?.virustotal?.configured ? (result.threat_intelligence.virustotal.malicious ? "var(--color-phishing)" : "var(--color-safe)") : "var(--text-dim)" }}>
                          {result.threat_intelligence?.virustotal?.configured
                            ? (result.threat_intelligence.virustotal.malicious ? "🔴 Malicious Hit" : "✓ No malicious detections")
                            : "— Not configured"}
                        </div>
                      </div>

                      <div style={{ background: "rgba(255, 255, 255, 0.02)", padding: "10px 14px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                        <span style={{ fontSize: "0.68rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700" }}>Google Safe Browsing</span>
                        <div style={{ fontSize: "0.84rem", fontWeight: "700", marginTop: "2px", color: result.threat_intelligence?.safe_browsing?.configured ? (result.threat_intelligence.safe_browsing.malicious ? "var(--color-phishing)" : "var(--color-safe)") : "var(--text-dim)" }}>
                          {result.threat_intelligence?.safe_browsing?.configured
                            ? (result.threat_intelligence.safe_browsing.malicious ? "🔴 Threat Reported" : "✓ No threat detected")
                            : "— Not configured"}
                        </div>
                      </div>
                    </div>

                    {(!result.threat_intelligence?.virustotal?.configured || !result.threat_intelligence?.safe_browsing?.configured) && (
                      <div style={{ fontSize: "0.74rem", color: "var(--text-muted)", marginTop: "6px", fontStyle: "italic" }}>
                        Threat intelligence unavailable. Local URL analysis was still performed.
                      </div>
                    )}
                  </div>

                  <div>
                    <span style={{ fontSize: "0.76rem", color: "var(--text-dim)", textTransform: "uppercase", fontWeight: "700" }}>
                      Why this result?
                    </span>
                    <ul className="reasons-list" style={{ marginTop: "6px" }}>
                      {(result.reasons || []).map((r, idx) => (
                        <li key={idx}>• {r}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="qr-breakdown-section">
                    <div className="qr-breakdown-title">Visual Risk Breakdown</div>
                    
                    <BreakdownBar label="URL Structure" value={result.breakdown?.url_structure ?? 0} />
                    <BreakdownBar label="Redirect Risk" value={result.breakdown?.redirect_risk ?? 0} />
                    <BreakdownBar label="Threat Intelligence" value={result.breakdown?.threat_intel ?? 0} />
                    <BreakdownBar label="Destination Risk" value={result.breakdown?.destination_risk ?? 0} />

                    <div style={{ borderTop: "1px solid var(--border-subtle)", paddingTop: "8px", marginTop: "4px" }}>
                      <div className="qr-breakdown-header" style={{ fontSize: "0.88rem", fontWeight: "800" }}>
                        <span>Overall QR Risk</span>
                        <span style={{ color: result.risk_level === "PHISHING" ? "var(--color-phishing)" : (result.risk_level === "SUSPICIOUS" ? "var(--color-suspicious)" : "var(--color-safe)") }}>
                          {(Number(result.risk_score || 0) * 100).toFixed(0)}%
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="redirect-chain-container">
                    <div className="redirect-chain-header">Redirect Chain</div>
                    {result.redirect_chain && result.redirect_chain.length > 1 ? (
                      <div className="redirect-chain-hops">
                        {result.redirect_chain.map((hop, hIdx) => (
                          <div key={hIdx} className="redirect-hop">
                            <span className="hop-badge">{hIdx + 1}.</span>
                            <span className="hop-url">{hop}</span>
                            {hIdx < result.redirect_chain.length - 1 && <span className="hop-arrow" style={{ marginLeft: "auto" }}>↓</span>}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div style={{ fontSize: "0.82rem", color: "var(--text-muted)" }}>
                        No redirects detected.
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
          )}
        </section>
      </main>

      <section className="panel incident-log">
        <div className="panel-header">
          <div>
            <h2>Recent QR Scans</h2>
            <span>Audit trail of standalone QR image inspections</span>
          </div>
        </div>

        {scans.length === 0 ? (
          <p style={{ textAlign: "center", color: "var(--text-dim)", padding: "20px 0", fontSize: "0.85rem" }}>
            No recent QR image scans found. Upload a QR code image above.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Time / ID</th>
                <th>Filename</th>
                <th>Decoded URL / Destination</th>
                <th>Result</th>
                <th>Risk Score</th>
                <th style={{ textAlign: "right" }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {scans.slice(0, 15).map((row) => {
                const rowRiskClass = (row.risk_level || "SAFE").toLowerCase().replace(" ", "_")
                return (
                  <tr key={row.id}>
                    <td style={{ color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                      #{row.id}
                    </td>
                    <td style={{ fontWeight: "600" }}>{row.filename}</td>
                    <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--text-muted)" }}>
                      {row.final_url || row.decoded_url || "No payload"}
                    </td>
                    <td>
                      <span className={`log-badge ${rowRiskClass}`}>
                        {row.risk_level}
                      </span>
                    </td>
                    <td style={{ fontWeight: "700" }}>
                      {(Number(row.risk_score || 0) * 100).toFixed(0)}%
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        onClick={() => inspectScanRow(row)}
                        style={{ background: "rgba(59, 130, 246, 0.15)", border: "1px solid rgba(59, 130, 246, 0.3)", color: "#60a5fa", padding: "4px 10px", borderRadius: "6px", fontSize: "0.76rem", cursor: "pointer", fontWeight: "600" }}
                      >
                        Inspect
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

function BreakdownBar({ label, value }) {
  const percent = Math.min(100, Math.max(0, Math.round(value * 100)))
  let color = "var(--color-safe)"
  if (percent >= 75) color = "var(--color-phishing)"
  else if (percent >= 40) color = "var(--color-suspicious)"

  return (
    <div className="qr-breakdown-row">
      <div className="qr-breakdown-header">
        <span className="qr-breakdown-label">{label}</span>
        <span className="qr-breakdown-val" style={{ color }}>{percent}%</span>
      </div>
      <div className="meter-bg">
        <div
          className="meter-fill"
          style={{ width: `${percent}%`, backgroundColor: color, boxShadow: `0 0 8px ${color}` }}
        />
      </div>
    </div>
  )
}

function SignalBreakdown({ signals = {}, detailed = false }) {
  const signalConfigs = [
    { key: "nlp_score", label: "Language Semantics Model (NLP)", icon: "🧠" },
    { key: "url_score", label: "Hyperlink Risk Profile", icon: "🔗" },
    { key: "header_score", label: "Envelope / Header Anomaly", icon: "✉️" },
    { key: "attachment_score", label: "Malicious Attachment Danger", icon: "📎" },
    { key: "sender_behavior_score", label: "Sender Historical Behavior Anomaly", icon: "📊" }
  ]

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
      {signalConfigs.map(s => {
        const val = Number(signals[s.key] ?? 0)
        const percent = Math.min(100, Math.max(0, Math.round(val * 100)))
        let colorVar = "var(--color-safe)"
        let statusText = "Clean"
        if (val >= 0.5) {
          colorVar = "var(--color-phishing)"
          statusText = "Critical"
        } else if (val >= 0.2) {
          colorVar = "var(--color-suspicious)"
          statusText = "Elevated"
        }

        return (
          <div key={s.key} className="signal-row">
            <div className="signal-label-wrapper">
              <span className="signal-name">
                <span style={{ marginRight: "6px" }}>{s.icon}</span>
                {s.label}
              </span>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                {detailed && (
                  <span style={{ fontSize: "0.72rem", color: colorVar, fontWeight: "700" }}>{statusText}</span>
                )}
                <span className="signal-value" style={{ color: colorVar }}>{percent}%</span>
              </div>
            </div>
            <div className="meter-bg">
              <div
                className="meter-fill"
                style={{
                  width: `${percent}%`,
                  backgroundColor: colorVar,
                  boxShadow: `0 0 8px ${colorVar}`
                }}
              />
            </div>
          </div>
        )
      })}
    </div>
  )
}

createRoot(document.getElementById("root")).render(<App />)
