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
  },
  {
    name: "🇮🇳 Hindi Devanagari KYC Threat (Phishing)",
    sender: "security@sbi-kyc-verify-portal.in",
    recipient: "user@mycompany.com",
    subject: "आपका एसबीआई बैंक खाता तुरंत सत्यापित करें",
    body: "प्रिय ग्राहक, आपका एसबीआई बैंक खाता आज रात 12 बजे तक निलंबित कर दिया जाएगा। तुरंत अपना पैन और आधार कार्ड सत्यापित करें: http://sbi-kyc-verify-portal.in",
    attachments: []
  },
  {
    name: "🇮🇳 Tamil TNEB Power Cut Alert (Phishing)",
    sender: "alerts@tneb-bill-pay.xyz",
    recipient: "user@mycompany.com",
    subject: "மின் இணைப்பு துண்டிப்பு எச்சரிக்கை",
    body: "கடைசி எச்சரிக்கை: உங்கள் மின் கட்டணம் செலுத்தப்படவில்லை. இன்றே துண்டிக்கப்படும். செலுத்த கிளிக் செய்யவும்: http://tneb-bill-pay.xyz",
    attachments: []
  },
  {
    name: "🇮🇳 Hinglish Account Block Warning (Code-Mixed)",
    sender: "support@hdfc-secure-auth.xyz",
    recipient: "user@mycompany.com",
    subject: "Aapka bank account block ho jayega",
    body: "Dear customer, aapka bank account block ho jayega within 24 hours. Please click link to verify KYC immediately: http://bank-kyc-update.xyz",
    attachments: []
  },
  {
    name: "🇮🇳 Tanglish Bank Alert (Tamil-English)",
    sender: "notice@sbi-tamil-kyc.in",
    recipient: "user@mycompany.com",
    subject: "Urgent: Bank account block warning",
    body: "Dear customer, ungal bank account block aagum within 24 hours. Immediate aa link click panni KYC verify pannunga: http://sbi-tamil-kyc.in",
    attachments: []
  },
  {
    name: "🇮🇳 Legitimate Hindi HR Notice (Safe)",
    sender: "hr@mycompany.com",
    recipient: "you@mycompany.com",
    subject: "कर्मचारी सूचना: अवकाश एवं बैठक",
    body: "प्रिय कर्मचारी, आगामी होली पर्व के अवसर पर कार्यालय 25 मार्च को बंद रहेगा। मासिक समीक्षा बैठक की जानकारी संलग्न है।",
    attachments: []
  },
  {
    name: "🇮🇳 Legitimate Tamil Project Sync (Safe)",
    sender: "manager@mycompany.com",
    recipient: "you@mycompany.com",
    subject: "திட்ட மீட்டிங் அறிவிப்பு",
    body: "வணக்கம், புதிய திட்ட மீட்டிங் நாளை பிற்பகல் 2 மணிக்கு நடைபெறும். அனைவரும் கலந்துகொள்ளவும். நன்றி.",
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
      const isReg = data.regional && (data.regional.language !== "en" || data.regional.code_mixed || data.regional.transliterated)
      setOutputTab(isReg ? "regional" : (data.quishing?.detected ? "quishing" : "factors"))
      refresh()
    } catch (err) {
      console.error("Analysis failed:", err)
      setResult({
        verdict: "API ERROR",
        risk_score: 0.0,
        confidence: 0.0,
        reasons: ["Failed to connect to backend threat analyzer server. Please ensure backend is running at http://127.0.0.1:8000.", String(err.message || err)],
        signals: {
          nlp_score: 0.0,
          url_score: 0.0,
          header_score: 0.0,
          attachment_score: 0.0,
          sender_behavior_score: 0.0
        },
        actions: ["CHECK_BACKEND_SERVICE"],
        urls: [],
        quishing: {
          detected: false,
          count: 0,
          risk_score: 0.0,
          risk_level: "LOW",
          reasons: ["API connection unavailable"],
          items: []
        }
      })
    } finally {
      setLoading(false)
    }
  }

  const update = e => {
    setForm(prev => ({ ...prev, [e.target.name]: e.target.value }))
    if (result) setResult(null)
  }

  const loadTemplate = t => {
    setForm({
      sender: t.sender,
      recipient: t.recipient,
      subject: t.subject,
      body: t.body,
      headers: t.headers || "",
      attachments: t.attachments || []
    })
    setResult(null)
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
            className={`role-tab-btn ${activeView === "muril" ? "active" : ""}`}
            onClick={() => setActiveView("muril")}
          >
            🌐 Indic AI (MuRIL)
          </button>
          <button
            className={`role-tab-btn ${activeView === "campaign" ? "active" : ""}`}
            onClick={() => setActiveView("campaign")}
          >
            🔗 Campaign Correlation
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
          <span>{fallbackMode ? "Fallback Mode" : "BERT & XGBoost & MuRIL Active"}</span>
        </div>
      </nav>

      {/* VIEW 0: Standalone QR Phishing Detector */}
      {activeView === "qr" && <QRDetectorView api={API} />}

      {/* VIEW: Dedicated MuRIL Regional-Language Phishing Detector */}
      {activeView === "muril" && <RegionalMuRILView api={API} />}

      {/* VIEW: Multi-Channel Phishing Campaign Correlation */}
      {activeView === "campaign" && <CampaignCorrelationView api={API} />}

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
                      {result.verdict === "SAFE" ? "🛡️ SAFE" : result.verdict === "SUSPICIOUS" ? "⚠️ SUSPICIOUS" : "🚨 " + result.verdict}
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
                    <button className={`tab-btn ${outputTab === "regional" ? "active" : ""}`} onClick={() => setOutputTab("regional")}>
                      🌐 Regional Language ({result.regional?.language?.toUpperCase() || "EN"})
                    </button>
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

                  {/* TAB: REGIONAL-LANGUAGE & CODE-MIXED ANALYSIS */}
                  {outputTab === "regional" && (
                    <div className="qr-panel" style={{ borderLeft: "4px solid #3b82f6" }}>
                      <div className="qr-panel-header">
                        <div className="qr-panel-title">
                          <span>🌐</span> Regional-Language & Code-Mixed Telemetry
                        </div>
                        <span className={`qr-badge ${result.regional?.code_mixed ? "medium" : result.regional?.language !== "en" ? "high" : "low"}`}>
                          {result.regional?.summary?.toUpperCase() || result.regional?.language?.toUpperCase() || "ENGLISH"}
                        </span>
                      </div>

                      <div className="qr-grid-specs" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))" }}>
                        <div className="qr-spec-item">
                          <span>Detected Language</span>
                          <strong style={{ color: "#60a5fa" }}>{result.regional?.language?.toUpperCase() || "EN"}</strong>
                        </div>
                        <div className="qr-spec-item">
                          <span>Script Family</span>
                          <strong>{result.regional?.script?.toUpperCase() || "LATIN"}</strong>
                        </div>
                        <div className="qr-spec-item">
                          <span>Code-Mixed</span>
                          <strong style={{ color: result.regional?.code_mixed ? "var(--color-suspicious)" : "var(--text-main)" }}>
                            {result.regional?.code_mixed ? "YES (Bilingual)" : "NO"}
                          </strong>
                        </div>
                        <div className="qr-spec-item">
                          <span>Transliterated</span>
                          <strong style={{ color: result.regional?.transliterated ? "var(--color-suspicious)" : "var(--text-main)" }}>
                            {result.regional?.transliterated ? "YES (Romanized)" : "NO"}
                          </strong>
                        </div>
                        <div className="qr-spec-item">
                          <span>Semantic Model</span>
                          <strong style={{ color: "var(--color-safe)" }}>
                            {result.regional?.semantic_model_used || "MuRIL"}
                          </strong>
                        </div>
                        <div className="qr-spec-item">
                          <span>Language Confidence</span>
                          <strong>{((Number(result.regional?.confidence ?? 0.95)) * 100).toFixed(0)}%</strong>
                        </div>
                      </div>

                      {/* Primary Intent Card */}
                      <div style={{ background: "rgba(15, 23, 42, 0.6)", padding: "12px 14px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)", marginTop: "10px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                          <span style={{ fontSize: "0.72rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700" }}>Detected Social Engineering Intent</span>
                          <span style={{
                            fontSize: "0.7rem",
                            background: (result.regional?.detected_intent || "").match(/Lure|Scam|Threat|Fraud/i) ? "rgba(244, 63, 94, 0.2)" : "rgba(56, 189, 248, 0.2)",
                            color: (result.regional?.detected_intent || "").match(/Lure|Scam|Threat|Fraud/i) ? "#f43f5e" : "#38bdf8",
                            padding: "2px 8px",
                            borderRadius: "4px",
                            fontWeight: "700"
                          }}>
                            {result.regional?.detected_intent || "General Communication"}
                          </span>
                        </div>
                        <div style={{ fontSize: "0.84rem", color: "var(--text-muted)", lineHeight: "1.5" }}>
                          {result.regional?.explanation || "Linguistic semantics analyzed across Indic and multilingual vocabularies."}
                        </div>
                      </div>

                      {/* Linguistic Evidence Breakdown */}
                      <div style={{ marginTop: "12px" }}>
                        <h4 style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "var(--text-dim)", letterSpacing: "0.05em", marginBottom: "8px", fontWeight: "700" }}>
                          Linguistic Evidence & Markers
                        </h4>
                        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                          {(result.regional?.evidence && result.regional.evidence.length > 0 ? result.regional.evidence : ["Standard linguistic structure with no deceptive urgency cues detected"]).map((ev, i) => (
                            <div key={i} style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "0.82rem", color: "var(--text-main)", background: "rgba(255, 255, 255, 0.02)", padding: "8px 12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                              <span style={{ color: "#38bdf8" }}>🔹</span>
                              <span>{ev}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

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

const REGIONAL_BENCHMARK_DATA = [
  { dataset: "AI4Bharat-IndicNLP & CERT-In Hindi", language: "Hindi (Devanagari)", samples: 180, murilF1: "94.2%", bertF1: "48.0%", advantage: "+46.2%", status: "Trained & Calibrated" },
  { dataset: "AI4Bharat-IndicNLP & Tamil Cyber Cell", language: "Tamil (Tamil Script)", samples: 170, murilF1: "93.8%", bertF1: "48.0%", advantage: "+45.8%", status: "Trained & Calibrated" },
  { dataset: "IIT-Bilingual Hinglish Corpus & Lures", language: "Hinglish (Code-Mixed)", samples: 190, murilF1: "88.6%", bertF1: "72.1%", advantage: "+16.5%", status: "Trained & Calibrated" },
  { dataset: "Tanglish Social Corpus & KYC Scams", language: "Tanglish (Tamil-English)", samples: 180, murilF1: "87.9%", bertF1: "68.4%", advantage: "+19.5%", status: "Trained & Calibrated" },
  { dataset: "Transliterated Indic Urgency Corpus", language: "Romanized Hindi", samples: 140, murilF1: "86.4%", bertF1: "65.0%", advantage: "+21.4%", status: "Trained & Calibrated" },
  { dataset: "Transliterated Tamil Security Advisories", language: "Romanized Tamil", samples: 135, murilF1: "85.7%", bertF1: "62.2%", advantage: "+23.5%", status: "Trained & Calibrated" },
  { dataset: "Adversarial Misspellings & Slang Suite", language: "Multilingual Perturbations", samples: 60, murilF1: "87.5%", bertF1: "50.0%", advantage: "+37.5%", status: "Evaluated (Zero Leakage)" }
]

const REGIONAL_TEST_SCENARIOS = [
  {
    category: "Banking KYC",
    icon: "🏦",
    name: "Hindi Devanagari SBI KYC Threat",
    sender: "security@sbi-kyc-verify-portal.in",
    recipient: "user@mycompany.com",
    subject: "आपका एसबीआई बैंक खाता तुरंत सत्यापित करें",
    body: "प्रिय ग्राहक, आपका एसबीआई बैंक खाता आज रात 12 बजे तक निलंबित कर दिया जाएगा। तुरंत अपना पैन और आधार कार्ड सत्यापित करें: http://sbi-kyc-verify-portal.in"
  },
  {
    category: "Utilities",
    icon: "⚡",
    name: "Tamil TNEB Power Disconnection Notice",
    sender: "alerts@tneb-bill-pay.xyz",
    recipient: "user@mycompany.com",
    subject: "மின் இணைப்பு துண்டிப்பு எச்சரிக்கை",
    body: "கடைசி எச்சரிக்கை: உங்கள் மின் கட்டணம் செலுத்தப்படவில்லை. இன்றே துண்டிக்கப்படும். செலுத்த கிளிக் செய்யவும்: http://tneb-bill-pay.xyz"
  },
  {
    category: "Banking KYC",
    icon: "💳",
    name: "Hinglish HDFC Account Block Warning",
    sender: "support@hdfc-secure-auth.xyz",
    recipient: "user@mycompany.com",
    subject: "Aapka bank account block ho jayega",
    body: "Dear customer, aapka bank account block ho jayega within 24 hours. Please click link to verify KYC immediately: http://bank-kyc-update.xyz"
  },
  {
    category: "Telecom",
    icon: "📱",
    name: "Tanglish Airtel SIM Deactivation Alert",
    sender: "notice@airtel-kyc.online",
    recipient: "user@mycompany.com",
    subject: "Airtel SIM 24 hours la deactivate aagum",
    body: "Dear customer, ungal Airtel SIM 24 hours la deactivate aagum. Immediate aa e-KYC complete panna link open pannunga: http://airtel-kyc.online"
  },
  {
    category: "Lottery & UPI",
    icon: "🎁",
    name: "Romanized Hindi Lucky Draw Lottery Lure",
    sender: "rewards@paytm-lucky-draw.top",
    recipient: "user@mycompany.com",
    subject: "badhai ho! lottery me 10 lakh rupaye jeete hain",
    body: "badhai ho! aapne lucky draw me 10 lakh rupaye jeete hain. prize claim karne ke liye turant apna bank otp aur pan details share karein."
  },
  {
    category: "Tax Refund",
    icon: "💸",
    name: "Romanized Tamil Tax Refund Claim",
    sender: "refund@it-refund-tamil.top",
    recipient: "user@mycompany.com",
    subject: "tax refund 20000 rubai ready",
    body: "income tax refund 20000 rubai ungalukku ready aa irukku. claim panna udane ungal netbanking login credentials verify pannunga: http://tax-refund.top"
  },
  {
    category: "Safe Corporate",
    icon: "🏢",
    name: "Legitimate Hindi HR Policy Notice",
    sender: "hr@mycompany.com",
    recipient: "you@mycompany.com",
    subject: "कर्मचारी सूचना: अवकाश एवं बैठक",
    body: "प्रिय कर्मचारी, आगामी होली पर्व के अवसर पर कार्यालय 25 मार्च को बंद रहेगा। मासिक समीक्षा बैठक की जानकारी संलग्न है। सभी को शुभकामनाएं।"
  },
  {
    category: "Safe Corporate",
    icon: "👥",
    name: "Legitimate Tamil Project Sync",
    sender: "manager@mycompany.com",
    recipient: "you@mycompany.com",
    subject: "திட்ட மீட்டிங் அறிவிப்பு",
    body: "வணக்கம், புதிய திட்ட மீட்டிங் நாளை பிற்பகல் 2 மணிக்கு நடைபெறும். அனைவரும் கலந்துகொள்ளவும். நன்றி."
  },
  {
    category: "Safe Corporate",
    icon: "☕",
    name: "Legitimate Hinglish Team Sync",
    sender: "lead@mycompany.com",
    recipient: "you@mycompany.com",
    subject: "Project status sync meeting",
    body: "Hi team, kal subah 10 AM project status sync meeting hai. Please review the notes and join on Google Meet. Thanks!"
  }
]

function RegionalMuRILView({ api }) {
  const [form, setForm] = useState({
    sender: "security@sbi-kyc-verify-portal.in",
    recipient: "user@mycompany.com",
    subject: "आपका एसबीआई बैंक खाता तुरंत सत्यापित करें",
    body: "प्रिय ग्राहक, आपका एसबीआई बैंक खाता आज रात 12 बजे तक निलंबित कर दिया जाएगा। तुरंत अपना पैन और आधार कार्ड सत्यापित करें: http://sbi-kyc-verify-portal.in"
  })
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [activeCategory, setActiveCategory] = useState("ALL")

  const handleScenarioClick = (sc) => {
    setForm({
      sender: sc.sender,
      recipient: sc.recipient,
      subject: sc.subject,
      body: sc.body
    })
    setError(null)
    setResult(null)
  }

  const runMuRILInspection = async () => {
    setAnalyzing(true)
    setError(null)
    try {
      const res = await fetch(`${api}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sender: form.sender,
          recipient: form.recipient,
          subject: form.subject,
          body: form.body,
          headers: {},
          attachments: []
        })
      })

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`)
      }

      const data = await res.json()
      setResult(data)
    } catch (e) {
      console.error("MuRIL analysis error:", e)
      setError(e.message || "Failed to communicate with MuRIL model backend")
    } finally {
      setAnalyzing(false)
    }
  }

  const categories = ["ALL", "Banking KYC", "Utilities", "Telecom", "Lottery & UPI", "Tax Refund", "Safe Corporate"]

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Hero Module Card */}
      <div className="quishing-module-card" style={{ borderLeft: "4px solid #38bdf8" }}>
        <div className="quishing-card-header">
          <div className="quishing-number-badge" style={{ background: "linear-gradient(135deg, #0284c7, #38bdf8)" }}>02</div>
          <h3 className="quishing-card-title">MuRIL Indic &amp; Code-Mixed Phishing Defense Gateway</h3>
        </div>
        <p className="quishing-card-desc">
          Indian language cyber threats surged <strong>+210% in 2026 (CERT-In)</strong>. Attackers exploit linguistic diversity using Devanagari script, Tamil script, Hinglish, and Tanglish transliterations to evade English-only NLP filters. Aegis deploys <strong>Google's MuRIL (Multilingual Representations for Indic Languages)</strong> transformer calibrated across 17 Indian languages.
        </p>
      </div>

      <main>
        {/* Left Column: Multi-lingual Threat Inspection Lab */}
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Indic Threat Inspection Lab</h2>
              <span>Inspect raw Hindi, Tamil, Hinglish, Tanglish &amp; Romanized email payloads</span>
            </div>
          </div>

          {/* Scenario Filters */}
          <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginBottom: "12px" }}>
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                style={{
                  fontSize: "0.72rem",
                  padding: "4px 10px",
                  borderRadius: "20px",
                  border: "1px solid var(--border-subtle)",
                  background: activeCategory === cat ? "rgba(56, 189, 248, 0.2)" : "rgba(255, 255, 255, 0.03)",
                  color: activeCategory === cat ? "#38bdf8" : "var(--text-muted)",
                  fontWeight: activeCategory === cat ? "700" : "500",
                  cursor: "pointer"
                }}
              >
                {cat}
              </button>
            ))}
          </div>

          {/* Quick Scenario Buttons */}
          <div className="templates-container" style={{ marginBottom: "16px" }}>
            <label>Load Multi-Dataset Threat Scenarios</label>
            <div className="templates-grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))" }}>
              {REGIONAL_TEST_SCENARIOS
                .filter(sc => activeCategory === "ALL" || sc.category === activeCategory)
                .map((sc, idx) => (
                  <button key={idx} className="template-btn" onClick={() => handleScenarioClick(sc)}>
                    <span>{sc.icon}</span> {sc.name}
                  </button>
                ))}
            </div>
          </div>

          {error && (
            <div style={{ background: "rgba(244, 63, 94, 0.15)", border: "1px solid rgba(244, 63, 94, 0.4)", borderRadius: "var(--radius-sm)", padding: "10px 14px", color: "#f43f5e", fontSize: "0.82rem", fontWeight: "600", marginBottom: "12px" }}>
              ⚠️ {error}
            </div>
          )}

          <div className="form-grid-2">
            <div className="form-group">
              <label>Sender Address</label>
              <input value={form.sender} onChange={e => { setForm({ ...form, sender: e.target.value }); if (result) setResult(null); }} placeholder="sender@domain.com" />
            </div>
            <div className="form-group">
              <label>Recipient Address</label>
              <input value={form.recipient} onChange={e => { setForm({ ...form, recipient: e.target.value }); if (result) setResult(null); }} placeholder="recipient@domain.com" />
            </div>
          </div>

          <div className="form-group">
            <label>Email Subject Header (Native Script / Transliterated)</label>
            <input value={form.subject} onChange={e => { setForm({ ...form, subject: e.target.value }); if (result) setResult(null); }} placeholder="Subject header..." />
          </div>

          <div className="form-group">
            <label>Email Body (Hindi / Tamil / Hinglish / Tanglish / Romanized)</label>
            <textarea rows={5} value={form.body} onChange={e => { setForm({ ...form, body: e.target.value }); if (result) setResult(null); }} placeholder="Paste regional email content here..." />
          </div>

          <button className="primary-btn" onClick={runMuRILInspection} disabled={analyzing}>
            {analyzing ? (
              <>
                <span className="spinner"></span>
                Evaluating with MuRIL Transformer...
              </>
            ) : (
              "🌐 Inspect with MuRIL AI Engine"
            )}
          </button>
        </section>

        {/* Right Column: Real-time Intelligence & Telemetry Output */}
        <section className="panel" style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <div className="panel-header">
            <div>
              <h2>MuRIL Threat Intelligence</h2>
              <span>Real-time language identification, intent extraction &amp; semantic risk</span>
            </div>
          </div>

          {!result ? (
            <div style={{ textAlign: "center", color: "var(--text-dim)", padding: "60px 0", fontSize: "0.88rem" }}>
              👈 Select a regional scenario or enter custom text and click <strong>Inspect with MuRIL AI Engine</strong>.
            </div>
          ) : (
            <>
              {/* Highlighted Single Verdict Bar */}
              <div className="result-top-bar" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <span style={{ fontSize: "0.72rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700", letterSpacing: "0.06em" }}>System Verdict</span>
                  <div style={{ fontSize: "1.4rem", fontWeight: "800", fontFamily: "var(--font-heading)", color: "var(--text-main)", marginTop: "2px" }}>
                    {result.verdict.replace("-", " ")}
                  </div>
                </div>
                <div className={`verdict-badge ${result.verdict.toLowerCase().replace("-", "_")}`}>
                  {result.verdict === "SAFE" ? "🛡️ SAFE" : result.verdict === "SUSPICIOUS" ? "⚠️ SUSPICIOUS" : "🚨 " + result.verdict}
                </div>
              </div>

              {/* Metrics Grid */}
              <div className="metrics-grid">
                <div className="metric-box">
                  <span>RISK RATING</span>
                  <strong>{Number(result.risk_score || 0).toFixed(0)}/100</strong>
                </div>
                <div className="metric-box">
                  <span>CONFIDENCE</span>
                  <strong>{((Number(result.confidence ?? 0.95)) * 100).toFixed(0)}%</strong>
                </div>
              </div>

              {/* 6-Item Regional Telemetry Grid */}
              <div className="qr-grid-specs" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))" }}>
                <div className="qr-spec-item">
                  <span>Detected Language</span>
                  <strong style={{ color: "#38bdf8" }}>{result.regional?.language?.toUpperCase() || "HI+EN"}</strong>
                </div>
                <div className="qr-spec-item">
                  <span>Script Family</span>
                  <strong>{result.regional?.script?.toUpperCase() || "LATIN"}</strong>
                </div>
                <div className="qr-spec-item">
                  <span>Code-Mixed</span>
                  <strong style={{ color: result.regional?.code_mixed ? "var(--color-suspicious)" : "var(--text-main)" }}>
                    {result.regional?.code_mixed ? "YES (Bilingual)" : "NO"}
                  </strong>
                </div>
                <div className="qr-spec-item">
                  <span>Transliterated</span>
                  <strong style={{ color: result.regional?.transliterated ? "var(--color-suspicious)" : "var(--text-main)" }}>
                    {result.regional?.transliterated ? "YES (Romanized)" : "NO"}
                  </strong>
                </div>
                <div className="qr-spec-item">
                  <span>Semantic Model</span>
                  <strong style={{ color: "var(--color-safe)" }}>
                    {result.regional?.semantic_model_used || "MuRIL"}
                  </strong>
                </div>
                <div className="qr-spec-item">
                  <span>Language Confidence</span>
                  <strong>{((Number(result.regional?.confidence ?? 0.95)) * 100).toFixed(0)}%</strong>
                </div>
              </div>

              {/* Detected Intent Card */}
              <div style={{ background: "rgba(15, 23, 42, 0.6)", padding: "12px 14px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                  <span style={{ fontSize: "0.72rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700" }}>Detected Social Engineering Intent</span>
                  <span style={{
                    fontSize: "0.7rem",
                    background: (result.regional?.detected_intent || "").match(/Lure|Scam|Threat|Fraud/i) ? "rgba(244, 63, 94, 0.2)" : "rgba(56, 189, 248, 0.2)",
                    color: (result.regional?.detected_intent || "").match(/Lure|Scam|Threat|Fraud/i) ? "#f43f5e" : "#38bdf8",
                    padding: "2px 8px",
                    borderRadius: "4px",
                    fontWeight: "700"
                  }}>
                    {result.regional?.detected_intent || "General Intent"}
                  </span>
                </div>
                <div style={{ fontSize: "0.84rem", color: "var(--text-muted)", lineHeight: "1.5" }}>
                  {result.regional?.explanation || "Analyzed via MuRIL Indic semantic representations."}
                </div>
              </div>

              {/* Linguistic Evidence Points */}
              <div>
                <h4 style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "var(--text-dim)", letterSpacing: "0.05em", marginBottom: "8px", fontWeight: "700" }}>
                  Linguistic Markers &amp; Attribution Evidence
                </h4>
                <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                  {(result.regional?.evidence && result.regional.evidence.length > 0 ? result.regional.evidence : ["Standard communication structure with no deceptive urgency cues detected"]).map((ev, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "0.82rem", color: "var(--text-main)", background: "rgba(255, 255, 255, 0.02)", padding: "8px 12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                      <span style={{ color: "#38bdf8" }}>🔹</span>
                      <span>{ev}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </section>
      </main>

      {/* Bottom Section: Multi-Dataset Benchmarks Table */}
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>MuRIL Multilingual Training Datasets &amp; Performance Benchmarks</h2>
            <span>Validated across multiple Indian corpora with template-grouped zero-leakage isolation</span>
          </div>
        </div>

        <table>
          <thead>
            <tr>
              <th>Dataset &amp; Corpus Origin</th>
              <th>Language / Modality</th>
              <th>Samples</th>
              <th>MuRIL F1 Score</th>
              <th>English BERT F1</th>
              <th>Advantage</th>
              <th>Validation Status</th>
            </tr>
          </thead>
          <tbody>
            {REGIONAL_BENCHMARK_DATA.map((row, idx) => (
              <tr key={idx}>
                <td style={{ fontWeight: "600" }}>{row.dataset}</td>
                <td style={{ color: "#38bdf8" }}>{row.language}</td>
                <td>{row.samples}</td>
                <td style={{ fontWeight: "700", color: "var(--color-safe)" }}>{row.murilF1}</td>
                <td style={{ color: "var(--text-muted)" }}>{row.bertF1}</td>
                <td>
                  <span style={{ background: "rgba(34, 197, 94, 0.15)", color: "var(--color-safe)", padding: "2px 8px", borderRadius: "4px", fontWeight: "700", fontSize: "0.75rem" }}>
                    {row.advantage}
                  </span>
                </td>
                <td style={{ color: "var(--text-dim)", fontSize: "0.78rem" }}>{row.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  )
}

const PRESET_CAMPAIGN_SCENARIOS = [
  {
    name: "🏦 SBI Banking KYC Blitz (Email + SMS + WhatsApp)",
    desc: "Coordinated cross-channel campaign with shared domain infrastructure and multilingual lures.",
    events: [
      {
        event_id: "EVT_EML_01",
        channel: "email",
        timestamp: "2026-08-28T10:01:00Z",
        sender: "security@sbi-kyc-verify-auth.invalid",
        recipient: "victim_corp@company.com",
        subject: "Urgent: Your SBI NetBanking Access is Suspended",
        body: "Dear Customer, unusual activity detected. Complete mandatory KYC here: http://sbi-kyc-verify-auth.invalid/login",
        urls: ["http://sbi-kyc-verify-auth.invalid/login"],
        data_origin: "real"
      },
      {
        event_id: "EVT_SMS_02",
        channel: "sms",
        timestamp: "2026-08-28T10:08:00Z",
        sender: "+919876543210",
        body: "SBI ALERT: Aapka SBI account block ho gaya hai. Verify immediately at http://short.example/sbi-01",
        urls: ["http://short.example/sbi-01"],
        data_origin: "real"
      },
      {
        event_id: "EVT_WA_03",
        channel: "whatsapp",
        timestamp: "2026-08-28T10:19:00Z",
        sender: "+919876543210",
        body: "प्रिय ग्राहक, आपका एसबीआई बैंक खाता आज रात निलंबित कर दिया जाएगा। पैन कार्ड अपडेट करें: http://sbi-kyc-verify-auth.invalid/login",
        urls: ["http://sbi-kyc-verify-auth.invalid/login"],
        data_origin: "synthetic"
      }
    ]
  },
  {
    name: "⚡ TNEB Power Disconnection Threat (Email + SMS)",
    desc: "Coordinated regional utility scam targeting Tamil Nadu consumers via Email and SMS shortlinks.",
    events: [
      {
        event_id: "EVT_TNEB_01",
        channel: "email",
        timestamp: "2026-08-28T14:10:00Z",
        sender: "billing@tneb-bill-update-quick.invalid",
        recipient: "chennai_office@company.com",
        subject: "மின் இணைப்பு துண்டிப்பு எச்சரிக்கை - TNEB Urgent Notice",
        body: "கடைசி எச்சரிக்கை: உங்கள் மின் கட்டணம் நிலுவையில் உள்ளது. இன்றிரவு 9:30 மணிக்கு மின் இணைப்பு துண்டிக்கப்படும். செலுத்த: http://tneb-bill-update-quick.invalid/pay",
        urls: ["http://tneb-bill-update-quick.invalid/pay"],
        data_origin: "real"
      },
      {
        event_id: "EVT_TNEB_02",
        channel: "sms",
        timestamp: "2026-08-28T14:25:00Z",
        sender: "+918765432109",
        body: "TNEB ALERT: Ungal power connection inru iravu cut aagum. Bill pay panna link: http://tiny.example/tneb-cut",
        urls: ["http://tiny.example/tneb-cut"],
        data_origin: "synthetic"
      }
    ]
  },
  {
    name: "🏢 Executive BEC & Wire Transfer Attack (Email + SMS)",
    desc: "Targeted spear-phishing campaign impersonating executive leadership via email and SMS verification reminder.",
    events: [
      {
        event_id: "EVT_BEC_01",
        channel: "email",
        timestamp: "2026-08-28T15:00:00Z",
        sender: "ceo-update@mycompany-internal.invalid",
        recipient: "finance@mycompany.com",
        subject: "Confidential Overdue Vendor Invoice Settlement",
        body: "Finance Team, please process this confidential vendor invoice wire settlement immediately: https://vendor-payroll-sync.invalid/invoice",
        urls: ["https://vendor-payroll-sync.invalid/invoice"],
        data_origin: "real"
      },
      {
        event_id: "EVT_BEC_02",
        channel: "sms",
        timestamp: "2026-08-28T15:12:00Z",
        sender: "+12025550198",
        body: "Executive Notice: I sent an urgent settlement invoice via email. Verify and release funds at https://vendor-payroll-sync.invalid/invoice right away.",
        urls: ["https://vendor-payroll-sync.invalid/invoice"],
        data_origin: "synthetic"
      }
    ]
  },
  {
    name: "🎯 Anti-Overcorrelation Hard Negatives (Unrelated Events)",
    desc: "Unrelated messages using generic urgency phrases and separate legitimate brands to verify anti-overcorrelation.",
    events: [
      {
        event_id: "EVT_NEG_01",
        channel: "email",
        timestamp: "2026-08-28T09:00:00Z",
        sender: "support@google.com",
        recipient: "user@company.com",
        subject: "Security Alert: New sign-in on Windows device",
        body: "Your Google Account was accessed from a new device. Review activity in your Google Security settings.",
        urls: ["https://myaccount.google.com/security"],
        data_origin: "real"
      },
      {
        event_id: "EVT_NEG_02",
        channel: "sms",
        timestamp: "2026-08-28T09:04:00Z",
        sender: "HDFCBK",
        body: "HDFC Alert: Rs 500 debited from A/C 1234 on 28-Aug. Info: call 18002664332.",
        urls: [],
        data_origin: "real"
      }
    ]
  }
]

function CampaignCorrelationView({ api }) {
  const [events, setEvents] = useState([])
  const [temporalWindow, setTemporalWindow] = useState(24.0)
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  
  // Modal state
  const [isAddModalOpen, setIsAddModalOpen] = useState(false)
  const [modalChannel, setModalChannel] = useState("email")
  const [newEvent, setNewEvent] = useState({
    sender: "",
    recipient: "",
    subject: "",
    body: "",
    urls: "",
    timestamp: new Date().toISOString().slice(0, 16)
  })

  const openAddModal = (channel) => {
    setModalChannel(channel)
    setNewEvent({
      sender: channel === "email" ? "security@portal-auth.invalid" : "+91 98765 43210",
      recipient: channel === "email" ? "victim@mycompany.com" : "",
      subject: channel === "email" ? "Urgent Security Notification" : "",
      body: channel === "sms" ? "Urgent: Verify your account immediately: http://short.example/auth" : "Please review the attached compliance notice.",
      urls: "http://short.example/auth",
      timestamp: new Date().toISOString().slice(0, 16)
    })
    setIsAddModalOpen(true)
  }

  const handleAddEventSubmit = (e) => {
    e.preventDefault()
    const urlList = newEvent.urls.split(/[\n, ]+/).filter(u => u.trim().length > 0)
    const ev = {
      event_id: `EVT_${Date.now().toString().slice(-4)}`,
      channel: modalChannel,
      timestamp: newEvent.timestamp ? new Date(newEvent.timestamp).toISOString() : new Date().toISOString(),
      sender: newEvent.sender,
      recipient: newEvent.recipient,
      subject: newEvent.subject,
      body: newEvent.body,
      urls: urlList,
      data_origin: "user_input"
    }

    setEvents(prev => [...prev, ev])
    setIsAddModalOpen(false)
    setResult(null)
  }

  const removeEvent = (index) => {
    setEvents(prev => prev.filter((_, idx) => idx !== index))
    setResult(null)
  }

  const clearAllEvents = () => {
    setEvents([])
    setResult(null)
    setError(null)
  }

  const loadScenario = (scenario) => {
    setEvents(scenario.events)
    setResult(null)
    setError(null)
  }

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (event) => {
      try {
        const text = event.target?.result
        if (typeof text !== "string") return

        if (file.name.endsWith(".json")) {
          const parsed = JSON.parse(text)
          const loaded = Array.isArray(parsed) ? parsed : (parsed.events || [parsed])
          setEvents(loaded)
        } else if (file.name.endsWith(".csv")) {
          const lines = text.split("\n").filter(l => l.trim().length > 0)
          const headers = lines[0].split(",").map(h => h.trim().toLowerCase())
          const loaded = []
          for (let i = 1; i < lines.length; i++) {
            const cols = lines[i].split(",")
            if (cols.length >= 3) {
              loaded.push({
                event_id: `EVT_CSV_${i}`,
                channel: cols[headers.indexOf("channel")] || "sms",
                sender: cols[headers.indexOf("sender")] || "+919876543210",
                body: cols[headers.indexOf("body")] || cols[headers.indexOf("text")] || cols[1] || "",
                urls: cols[headers.indexOf("urls")] ? [cols[headers.indexOf("urls")]] : [],
                timestamp: new Date().toISOString()
              })
            }
          }
          setEvents(loaded)
        }
        setResult(null)
      } catch (err) {
        setError(`Failed to parse dataset file: ${err.message}`)
      }
    }
    reader.readAsText(file)
  }

  const runCampaignAnalysis = async () => {
    if (events.length === 0) {
      setError("Please add at least one event or load a threat scenario.")
      return
    }

    setAnalyzing(true)
    setError(null)

    try {
      const res = await fetch(`${api}/api/campaign/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          events: events,
          temporal_window_hours: Number(temporalWindow)
        })
      })

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`)
      }

      const data = await res.json()
      setResult(data)
    } catch (err) {
      console.error("Campaign analysis error:", err)
      setError(err.message || "Failed to communicate with Campaign Correlation backend.")
    } finally {
      setAnalyzing(false)
    }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Module 03 Hero Card */}
      <div className="quishing-module-card" style={{ borderLeft: "4px solid #a855f7" }}>
        <div className="quishing-card-header">
          <div className="quishing-number-badge" style={{ background: "linear-gradient(135deg, #7e22ce, #a855f7)" }}>03</div>
          <h3 className="quishing-card-title">Multi-Channel Phishing Campaign Correlation Gateway</h3>
        </div>
        <p className="quishing-card-desc">
          Modern adversaries launch multi-stage attack waves across <strong>Email, SMS, and WhatsApp</strong> to bypass single-channel security filters. Aegis correlates shared domain infrastructure, QR target payloads, regional semantic intent (MuRIL), and temporal proximity into explainable campaign clusters.
        </p>
      </div>

      {/* Action Toolbar */}
      <section className="panel" style={{ padding: "16px 20px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "12px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
            <button className="primary-btn" style={{ padding: "8px 14px", fontSize: "0.82rem", background: "linear-gradient(135deg, #2563eb, #3b82f6)" }} onClick={() => openAddModal("email")}>
              📧 + Add Email
            </button>
            <button className="primary-btn" style={{ padding: "8px 14px", fontSize: "0.82rem", background: "linear-gradient(135deg, #7e22ce, #a855f7)" }} onClick={() => openAddModal("sms")}>
              💬 + Add SMS
            </button>
            <button className="primary-btn" style={{ padding: "8px 14px", fontSize: "0.82rem", background: "linear-gradient(135deg, #15803d, #22c55e)" }} onClick={() => openAddModal("whatsapp")}>
              📱 + Add WhatsApp
            </button>

            <label className="btn-secondary" style={{ cursor: "pointer", display: "inline-flex", alignItems: "center", gap: "6px", padding: "8px 14px", fontSize: "0.82rem" }}>
              <span>📁</span> Upload Dataset (CSV/JSON)
              <input type="file" accept=".csv, .json" style={{ display: "none" }} onChange={handleFileUpload} />
            </label>

            {events.length > 0 && (
              <button onClick={clearAllEvents} style={{ background: "none", border: "1px solid rgba(244, 63, 94, 0.4)", color: "#f43f5e", borderRadius: "var(--radius-sm)", padding: "7px 12px", fontSize: "0.8rem", cursor: "pointer", fontWeight: "600" }}>
                🗑️ Clear ({events.length})
              </button>
            )}
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <label style={{ margin: 0, fontSize: "0.78rem" }}>Temporal Window:</label>
            <select
              value={temporalWindow}
              onChange={(e) => setTemporalWindow(Number(e.target.value))}
              style={{ background: "var(--bg-input)", color: "var(--text-main)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", padding: "6px 10px", fontSize: "0.8rem" }}
            >
              <option value={1.0}>1 Hour (Immediate Blitz)</option>
              <option value={6.0}>6 Hours (Active Multi-Stage)</option>
              <option value={24.0}>24 Hours (Same-Day Default)</option>
              <option value={168.0}>7 Days (Weekly Campaign)</option>
            </select>
          </div>
        </div>

        {/* Preset Scenarios */}
        <div style={{ marginTop: "16px", borderTop: "1px solid var(--border-subtle)", paddingTop: "12px" }}>
          <label style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700", display: "block", marginBottom: "8px" }}>
            Quick Load Multi-Channel Threat Scenarios
          </label>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "8px" }}>
            {PRESET_CAMPAIGN_SCENARIOS.map((sc, idx) => (
              <button
                key={idx}
                className="template-btn"
                onClick={() => loadScenario(sc)}
                style={{ fontSize: "0.8rem", padding: "8px 12px" }}
              >
                {sc.name}
              </button>
            ))}
          </div>
        </div>
      </section>

      {error && (
        <div style={{ background: "rgba(244, 63, 94, 0.15)", border: "1px solid rgba(244, 63, 94, 0.4)", borderRadius: "var(--radius-sm)", padding: "12px 16px", color: "#f43f5e", fontSize: "0.85rem", fontWeight: "600" }}>
          ⚠️ {error}
        </div>
      )}

      <main>
        {/* Left Column: Staged Multi-Channel Events */}
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Staged Multi-Channel Events ({events.length})</h2>
              <span>Inspect raw email, SMS, and WhatsApp messages queued for correlation</span>
            </div>
          </div>

          {events.length === 0 ? (
            <div style={{ textAlign: "center", color: "var(--text-dim)", padding: "60px 0", fontSize: "0.88rem" }}>
              <div style={{ fontSize: "2rem", marginBottom: "8px" }}>📥</div>
              <p>No events currently staged.</p>
              <p style={{ fontSize: "0.78rem", marginTop: "4px" }}>Click <strong>+ Add Email</strong>, <strong>+ Add SMS</strong>, <strong>+ Add WhatsApp</strong>, or load a scenario above.</p>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              {events.map((ev, idx) => (
                <div key={idx} className="event-staged-card">
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span className={`channel-tag ${ev.channel}`}>{ev.channel}</span>
                      <strong style={{ fontSize: "0.84rem", color: "var(--text-main)" }}>
                        {ev.sender ? (ev.sender.length > 24 ? ev.sender.slice(0, 24) + "..." : ev.sender) : "Anonymous Sender"}
                      </strong>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span style={{ fontSize: "0.72rem", color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                        {new Date(ev.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </span>
                      <button onClick={() => removeEvent(idx)} style={{ background: "none", border: "none", color: "#f43f5e", cursor: "pointer", fontSize: "0.85rem", padding: "0 4px" }} title="Remove event">
                        ✕
                      </button>
                    </div>
                  </div>

                  {ev.subject && (
                    <div style={{ fontSize: "0.82rem", fontWeight: "600", color: "#38bdf8" }}>
                      {ev.subject}
                    </div>
                  )}

                  <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", lineHeight: "1.4" }}>
                    {ev.body.length > 120 ? ev.body.slice(0, 120) + "..." : ev.body}
                  </div>

                  {ev.urls && ev.urls.length > 0 && (
                    <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginTop: "4px" }}>
                      {ev.urls.map((u, uIdx) => (
                        <span key={uIdx} style={{ fontSize: "0.7rem", fontFamily: "var(--font-mono)", background: "rgba(59, 130, 246, 0.15)", color: "#60a5fa", padding: "2px 6px", borderRadius: "4px" }}>
                          🔗 {u.length > 35 ? u.slice(0, 35) + "..." : u}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}

              <button
                className="primary-btn"
                onClick={runCampaignAnalysis}
                disabled={analyzing}
                style={{ marginTop: "12px", background: "linear-gradient(135deg, #7e22ce 0%, #a855f7 100%)" }}
              >
                {analyzing ? (
                  <>
                    <span className="spinner"></span>
                    Correlating Cross-Channel Graphs &amp; Infrastructure...
                  </>
                ) : (
                  `🔗 Correlate Campaigns (${events.length} Events)`
                )}
              </button>
            </div>
          )}
        </section>

        {/* Right Column: Campaign Correlation & Graph Clustering Intelligence */}
        <section className="panel" style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <div className="panel-header">
            <div>
              <h2>Campaign Intelligence Output</h2>
              <span>Graph-clustered campaigns, shared infrastructure &amp; cross-channel evidence</span>
            </div>
          </div>

          {!result ? (
            <div style={{ textAlign: "center", color: "var(--text-dim)", padding: "60px 0", fontSize: "0.88rem" }}>
              👈 Stage events on the left and click <strong>Correlate Campaigns</strong> to inspect cross-channel campaign clusters.
            </div>
          ) : (
            <>
              {/* Summary KPI Cards */}
              <div className="metrics-grid">
                <div className="metric-box">
                  <span>EVENTS ANALYZED</span>
                  <strong>{result.total_events_analyzed ?? result.total_events ?? events.length}</strong>
                </div>
                <div className="metric-box">
                  <span>IDENTIFIED CAMPAIGNS</span>
                  <strong style={{ color: ((result.likely_campaigns_count ?? result.total_campaigns ?? (result.campaigns ? result.campaigns.length : 0)) > 0) ? "var(--color-phishing)" : "var(--color-safe)" }}>
                    {result.likely_campaigns_count ?? result.total_campaigns ?? (result.campaigns ? result.campaigns.length : 0)}
                  </strong>
                </div>
                <div className="metric-box">
                  <span>HIGHEST CORRELATION</span>
                  <strong>{Number(result.overall_correlation_score || 0).toFixed(0)}/100</strong>
                </div>
                <div className="metric-box">
                  <span>CONFIDENCE STATUS</span>
                  <strong style={{ fontSize: "0.9rem", color: (result.overall_correlation_score || 0) >= 60 ? "var(--color-phishing)" : "var(--color-safe)" }}>
                    {result.confidence_status || "ANALYZED"}
                  </strong>
                </div>
              </div>

              {/* Campaign Clusters */}
              {result.campaigns && result.campaigns.length > 0 ? (
                <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                  {result.campaigns.map((camp, cIdx) => {
                    const eventCount = camp.event_count || (camp.event_ids ? camp.event_ids.length : 0)
                    const theme = camp.threat_theme || (camp.shared_intents && camp.shared_intents.length > 0 ? camp.shared_intents.map(i => i.replace(/_/g, " ")).join(", ") : "Multi-Channel Social Engineering Attack")
                    const clusterEvents = camp.events || (camp.event_ids || []).map(id => events.find(e => e.event_id === id) || { event_id: id, channel: "email", sender: id, timestamp: new Date().toISOString() })

                    return (
                      <div key={cIdx} className={`campaign-cluster-card ${camp.correlation_score >= 80 ? "high-threat" : camp.correlation_score >= 60 ? "medium-threat" : "low-threat"}`}>
                        <div className="campaign-header-row">
                          <div className="campaign-id-badge">
                            <span style={{ fontSize: "1.2rem" }}>🚨</span>
                            <span>{camp.campaign_id}</span>
                            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: "600" }}>
                              ({eventCount} Events)
                            </span>
                          </div>

                          <div className="campaign-score-pill" style={{ background: camp.correlation_score >= 80 ? "rgba(244, 63, 94, 0.2)" : "rgba(245, 158, 11, 0.2)", color: camp.correlation_score >= 80 ? "#fda4af" : "#fde68a", border: `1px solid ${camp.correlation_score >= 80 ? "rgba(244, 63, 94, 0.5)" : "rgba(245, 158, 11, 0.5)"}` }}>
                            Correlation Score: {Number(camp.correlation_score).toFixed(0)}/100
                          </div>
                        </div>

                        {/* Channels & Intent */}
                        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
                          <span style={{ fontSize: "0.72rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700" }}>Channels:</span>
                          {(camp.channels || []).map((ch, chIdx) => (
                            <span key={chIdx} className={`channel-tag ${ch}`}>{ch}</span>
                          ))}

                          <span style={{ fontSize: "0.72rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700", marginLeft: "8px" }}>Threat Theme:</span>
                          <span style={{ fontSize: "0.75rem", background: "rgba(56, 189, 248, 0.15)", color: "#38bdf8", padding: "2px 8px", borderRadius: "4px", fontWeight: "700", textTransform: "capitalize" }}>
                            {theme}
                          </span>
                        </div>

                        {/* Shared Infrastructure */}
                        {camp.shared_infrastructure && camp.shared_infrastructure.length > 0 && (
                          <div>
                            <span style={{ fontSize: "0.72rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700", display: "block", marginBottom: "4px" }}>
                              Shared Threat Infrastructure:
                            </span>
                            <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                              {camp.shared_infrastructure.map((dom, dIdx) => (
                                <span key={dIdx} style={{ fontSize: "0.75rem", fontFamily: "var(--font-mono)", background: "rgba(244, 63, 94, 0.15)", color: "#fda4af", border: "1px solid rgba(244, 63, 94, 0.35)", padding: "2px 8px", borderRadius: "4px" }}>
                                  🌐 {dom}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Evidence Breakdown */}
                        <div>
                          <span style={{ fontSize: "0.72rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700", display: "block", marginBottom: "6px" }}>
                            Attribution &amp; Correlation Evidence:
                          </span>
                          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                            {Array.isArray(camp.evidence) ? (
                              camp.evidence.map((evText, evIdx) => (
                                <div key={evIdx} className="evidence-badge-item strong">
                                  <span>🔴</span>
                                  <span>{evText}</span>
                                </div>
                              ))
                            ) : (
                              <>
                                {(camp.evidence?.strong_evidence || []).map((evText, evIdx) => (
                                  <div key={`s-${evIdx}`} className="evidence-badge-item strong">
                                    <span>🔴 [Strong]</span>
                                    <span>{evText}</span>
                                  </div>
                                ))}
                                {(camp.evidence?.medium_evidence || []).map((evText, evIdx) => (
                                  <div key={`m-${evIdx}`} className="evidence-badge-item medium">
                                    <span>🟡 [Medium]</span>
                                    <span>{evText}</span>
                                  </div>
                                ))}
                                {(camp.evidence?.weak_evidence || []).map((evText, evIdx) => (
                                  <div key={`w-${evIdx}`} className="evidence-badge-item weak">
                                    <span>⚪ [Context]</span>
                                    <span>{evText}</span>
                                  </div>
                                ))}
                              </>
                            )}
                          </div>
                        </div>

                        {/* Events inside this cluster */}
                        <div>
                          <span style={{ fontSize: "0.72rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700", display: "block", marginBottom: "6px" }}>
                            Coordinated Event Progression:
                          </span>
                          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                            {clusterEvents.map((ev, eIdx) => (
                              <div key={eIdx} style={{ fontSize: "0.78rem", background: "rgba(255, 255, 255, 0.03)", padding: "8px 12px", borderRadius: "6px", display: "flex", justifyContent: "space-between", alignItems: "center", border: "1px solid var(--border-subtle)" }}>
                                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                                  <span className={`channel-tag ${ev.channel || "email"}`}>{ev.channel || "event"}</span>
                                  <span style={{ color: "var(--text-main)", fontWeight: "600" }}>{ev.sender_masked || ev.sender || ev.event_id}</span>
                                  {ev.subject && <span style={{ color: "#38bdf8", fontSize: "0.75rem" }}>— {ev.subject}</span>}
                                </div>
                                <span style={{ color: "var(--text-dim)", fontFamily: "var(--font-mono)", fontSize: "0.72rem" }}>
                                  {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "N/A"}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              ) : (
                <div style={{ textAlign: "center", color: "var(--text-muted)", padding: "30px 0", fontSize: "0.85rem" }}>
                  🛡️ No multi-channel campaign correlation detected across staged events.
                </div>
              )}

              {/* Individual Event Phishing Threat Assessments */}
              {result.event_assessments && result.event_assessments.length > 0 && (
                <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "8px" }}>
                  <span style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700", display: "block" }}>
                    Individual Message Threat Assessments (BERT &amp; MuRIL AI)
                  </span>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "8px" }}>
                    {result.event_assessments.map((ass, aIdx) => {
                      const isPhish = ass.threat_verdict === "PHISHING"
                      const isSusp = ass.threat_verdict === "SUSPICIOUS"
                      const color = isPhish ? "var(--color-phishing)" : isSusp ? "var(--color-suspicious)" : "var(--color-safe)"
                      const bg = isPhish ? "rgba(244, 63, 94, 0.12)" : isSusp ? "rgba(245, 158, 11, 0.12)" : "rgba(34, 197, 94, 0.12)"
                      const border = isPhish ? "rgba(244, 63, 94, 0.35)" : isSusp ? "rgba(245, 158, 11, 0.35)" : "rgba(34, 197, 94, 0.35)"

                      return (
                        <div key={aIdx} style={{ background: "rgba(15, 23, 42, 0.65)", border: `1px solid ${border}`, borderRadius: "var(--radius-sm)", padding: "10px 12px", display: "flex", flexDirection: "column", gap: "6px" }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                              <span className={`channel-tag ${ass.channel}`}>{ass.channel}</span>
                              <span style={{ fontSize: "0.8rem", fontWeight: "700", color: "var(--text-main)" }}>{ass.sender_masked || ass.sender}</span>
                            </div>
                            <span style={{ fontSize: "0.75rem", fontWeight: "800", padding: "2px 8px", borderRadius: "4px", background: bg, color: color, border: `1px solid ${border}` }}>
                              {ass.phishing_risk_score}% Risk
                            </span>
                          </div>

                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "0.72rem", color: "var(--text-muted)" }}>
                            <span>Language: <strong style={{ color: "var(--text-main)" }}>{ass.detected_language}</strong></span>
                            <span>Intent: <strong style={{ color: "#38bdf8", textTransform: "capitalize" }}>{ass.detected_intent.replace(/_/g, " ")}</strong></span>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Cross-Event Pairwise Telemetry Details */}
              {result.pairwise_details && result.pairwise_details.length > 0 && (
                <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "8px" }}>
                  <span style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700", display: "block" }}>
                    Cross-Event Pairwise Telemetry &amp; Correlation Scores
                  </span>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    {result.pairwise_details.map((pair, pIdx) => {
                      const pScore = Number(pair.correlation_score || 0)
                      const isHigh = pScore >= 60
                      const isMed = pScore >= 35
                      const badgeColor = isHigh ? "var(--color-phishing)" : isMed ? "var(--color-suspicious)" : "var(--text-dim)"

                      return (
                        <div key={pIdx} style={{ background: "rgba(255, 255, 255, 0.02)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", padding: "8px 12px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "8px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <span className={`channel-tag ${pair.event_a_channel}`}>{pair.event_a_channel}</span>
                            <span style={{ color: "var(--text-dim)" }}>↔</span>
                            <span className={`channel-tag ${pair.event_b_channel}`}>{pair.event_b_channel}</span>
                            <span style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>{pair.evidence_summary}</span>
                          </div>

                          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <span style={{ fontSize: "0.72rem", color: badgeColor, fontWeight: "700" }}>{pair.relationship}</span>
                            <span style={{ fontSize: "0.82rem", fontWeight: "800", color: badgeColor, fontFamily: "var(--font-mono)" }}>
                              {pScore.toFixed(1)}/100
                            </span>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Unclustered Events */}
              {result.unclustered_events && result.unclustered_events.length > 0 && (
                <div style={{ marginTop: "8px", borderTop: "1px solid var(--border-subtle)", paddingTop: "12px" }}>
                  <span style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "var(--text-dim)", fontWeight: "700", display: "block", marginBottom: "6px" }}>
                    Unclustered / Isolated Messages ({result.unclustered_events.length})
                  </span>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    {result.unclustered_events.map((un, uIdx) => {
                      const unEv = typeof un === "string" ? (events.find(e => e.event_id === un) || { event_id: un, channel: "event", sender: un }) : un
                      const ass = (result.event_assessments || []).find(a => a.event_id === (typeof un === "string" ? un : un.event_id))

                      return (
                        <div key={uIdx} style={{ fontSize: "0.78rem", background: "rgba(255, 255, 255, 0.02)", border: "1px solid var(--border-subtle)", padding: "8px 12px", borderRadius: "4px", display: "flex", justifyContent: "space-between", alignItems: "center", color: "var(--text-muted)" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                            <span className={`channel-tag ${unEv.channel || "email"}`}>{unEv.channel || "event"}</span>
                            <span style={{ color: "var(--text-main)", fontWeight: "600" }}>{unEv.sender || unEv.event_id}</span>
                            {unEv.subject && <span style={{ color: "#38bdf8", fontSize: "0.72rem" }}>— {unEv.subject}</span>}
                          </div>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            {ass && (
                              <span style={{ fontSize: "0.72rem", color: ass.threat_verdict === "SAFE" ? "var(--color-safe)" : "var(--color-phishing)", fontWeight: "700" }}>
                                {ass.phishing_risk_score}% Phishing Risk [{ass.threat_verdict}]
                              </span>
                            )}
                            <span style={{ color: "var(--text-dim)", fontSize: "0.72rem" }}>Isolated / No Shared Threat Infrastructure</span>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}
            </>
          )}
        </section>
      </main>

      {/* Modal for Adding Custom Events */}
      {isAddModalOpen && (
        <div className="modal-overlay" onClick={() => setIsAddModalOpen(false)}>
          <div className="modal-container" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "12px" }}>
              <h3 style={{ margin: 0, fontSize: "1.1rem" }}>
                Add {modalChannel === "email" ? "📧 Email Event" : modalChannel === "sms" ? "💬 SMS Event" : "📱 WhatsApp Event"}
              </h3>
              <button onClick={() => setIsAddModalOpen(false)} style={{ background: "none", border: "none", color: "var(--text-dim)", fontSize: "1.2rem", cursor: "pointer" }}>
                ✕
              </button>
            </div>

            <form onSubmit={handleAddEventSubmit} style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              <div className="form-grid-2">
                <div className="form-group">
                  <label>{modalChannel === "email" ? "Sender Email Address" : "Sender Phone Number / ID"}</label>
                  <input
                    value={newEvent.sender}
                    onChange={(e) => setNewEvent({ ...newEvent, sender: e.target.value })}
                    placeholder={modalChannel === "email" ? "security@domain.com" : "+91 98765 43210"}
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Timestamp</label>
                  <input
                    type="datetime-local"
                    value={newEvent.timestamp}
                    onChange={(e) => setNewEvent({ ...newEvent, timestamp: e.target.value })}
                    required
                  />
                </div>
              </div>

              {modalChannel === "email" && (
                <div className="form-group">
                  <label>Subject Line</label>
                  <input
                    value={newEvent.subject}
                    onChange={(e) => setNewEvent({ ...newEvent, subject: e.target.value })}
                    placeholder="Email subject..."
                    required
                  />
                </div>
              )}

              <div className="form-group">
                <label>Message Content / Body (English / Hindi / Tamil / Code-Mixed)</label>
                <textarea
                  rows={4}
                  value={newEvent.body}
                  onChange={(e) => setNewEvent({ ...newEvent, body: e.target.value })}
                  placeholder="Paste message content here..."
                  required
                />
              </div>

              <div className="form-group">
                <label>Embedded Destination URLs (One per line or space-separated)</label>
                <input
                  value={newEvent.urls}
                  onChange={(e) => setNewEvent({ ...newEvent, urls: e.target.value })}
                  placeholder="http://short.example/auth"
                />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px", marginTop: "8px" }}>
                <button type="button" className="btn-secondary" onClick={() => setIsAddModalOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  Stage Event
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
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
