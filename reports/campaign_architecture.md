# Multi-Channel Phishing Campaign Correlation Architecture

## 1. System Topology

```
                   MULTI-CHANNEL INGRESS
                            │
       ┌────────────────────┼────────────────────┐
       │                    │                    │
     EMAIL                 SMS                WHATSAPP
  (Header, Body,       (Sender No,        (Sender ID, Text,
   URLs, QR, Att)       Body, URLs)        URLs, Timestamp)
       │                    │                    │
       └────────────────────┼────────────────────┘
                            ▼
              CANONICAL NORMALIZATION ENGINE
             (Domain, eTLD+1, Phone Masking,
             UTC Time, Language Identification)
                            │
                            ▼
                ENTITY & FEATURE EXTRACTION
        ┌───────────────────┼───────────────────┐
        │                   │                   │
  INFRASTRUCTURE        MULTILINGUAL        TEMPORAL &
  (URLs, Domains,         SEMANTICS           SENDER
   Redirects, QR)       (MuRIL / BERT)       (Decay)
        │                   │                   │
        └───────────────────┼───────────────────┘
                            ▼
           PAIRWISE CORRELATION ENGINE (0–100)
             [Anti-Overcorrelation Penalty]
                            │
                            ▼
             GRAPH-BASED CLUSTERING ENGINE
               (Connected Components ≥ 60)
                            │
                            ▼
             EXPLAINABLE CAMPAIGN TELEMETRY
         (Campaigns, Clusters, Categorized Evidence)
```

## 2. Signal Dimensions & Formulations

### A. Infrastructure Signal ($S_{\text{infra}} \in [0, 1]$)
* **Exact URL Match**: $1.00$
* **Registrable Domain (eTLD+1) Match**: $0.88$
* **QR Code Payload Overlap**: $0.95$
* **Attachment Filename / Hash Match**: $0.80$
* **Benign Domain Suppression**: Shared public platforms (e.g. `google.com`, `bit.ly`) without custom malicious path are capped at $0.20$ to prevent false correlation.

### B. Multilingual Semantic Signal ($S_{\text{content}} \in [0, 1]$)
* Powered by **MuRIL (Multilingual Representations for Indic Languages)**.
* Evaluates cross-lingual social-engineering intent across English, Hindi, Tamil, Hinglish, and Tanglish.
* Meaningful Jaccard keyword overlap with generic boilerplate suppression (terms like *"urgent"*, *"verify"*, *"account"* are filtered).

### C. Temporal Decay Function ($S_{\text{temporal}} \in [0, 1]$)
$$\Delta t = |t_A - t_B|$$
$$S_{\text{temporal}}(\Delta t) = \begin{cases} 1.00 & \text{if } \Delta t \le 1\text{ hour} \\ 0.85 & \text{if } 1 < \Delta t \le 6\text{ hours} \\ 0.70 & \text{if } 6 < \Delta t \le 24\text{ hours} \\ 0.40 & \text{if } 24 < \Delta t \le 168\text{ hours (7 days)} \\ 0.10 & \text{if } \Delta t > 7\text{ days} \end{cases}$$

### D. Sender Identity Signal ($S_{\text{sender}} \in [0, 1]$)
* Canonical E.164 phone number match: $0.90$
* Sender domain match: $0.85$

## 3. Decision & Graph Clustering
* Edge weight: $W(u, v) = \text{CompositeScore}(u, v) \in [0, 100]$
* Adjacency threshold: $W(u, v) \ge 60.0$
* Graph partitioning: Connected components yield distinct campaigns $C_1, C_2, \dots$
* Singletons ($< 60.0$) remain unclustered.
