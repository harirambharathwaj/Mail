# Security Audit Report

## Executive Summary
A comprehensive security review was performed across the API endpoints, input validation layer, attachment/PDF processing, QR code scanning engine, SSRF protections, threat intelligence services, and secret management.

## 1. Server-Side Request Forgery (SSRF) Audit
- **Status**: **PASS (HARDENED)**
- **Component**: `app/services/qr_resolver.py` & `threat_intel.py`
- **Protection Mechanics**:
  - IP Address Filtering: Explicit blocking of `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16` (Cloud metadata endpoint `169.254.169.254`), `172.16.0.0/12`, `192.168.0.0/16`, IPv6 loopback (`::1/128`), and link-local (`fe80::/10`).
  - Hostname Restrictions: Explicit blocking of `localhost`, `instance-data`, `metadata.google.internal`, `.local`, and `.internal` suffixes.
  - DNS Resolution Validation: Resolves hostnames via `socket.getaddrinfo` prior to issuing HTTP requests to ensure target IP is routable and public.
  - Redirect Validation: Enforces SSRF checks on **every hop** of HTTP redirect chains (`max_redirects=5`), halting immediately if a redirect attempts to pivot to a private or internal IP address.
  - Resource Bounds: Enforces connect/read timeouts (3.5 seconds per hop) and streaming limits to prevent connection exhaustion.

## 2. File Upload & Attachment Processing Audit
- **Status**: **PASS (HARDENED)**
- **Component**: `app/main.py`, `app/services/analyzers.py`, `app/services/qr_scanner.py`
- **Protections**:
  - MIME & Extension Enforcement: Strict whitelisting of permitted extensions (`.png`, `.jpg`, `.jpeg`, `.webp`, `.pdf`).
  - Size Bounds: 10 MB maximum payload limit enforced on `/api/qr/analyze` and attachment parser to prevent memory exhaustion DoS.
  - Path Traversal Shielding: Filenames processed via standard library base paths; uploaded content is handled strictly in-memory or in isolated temporary buffers without writing to unvalidated relative paths.
  - Clean Initial State: Initial attachment state defaults strictly to `attachments = []` across frontend, backend schemas, and database fixtures. Sample demo files load only upon explicit user trigger ("Load Demo").

## 3. PDF Security & Rendering Audit
- **Status**: **PASS**
- **Component**: `app/services/qr_scanner.py` (`scan_pdf_bytes`)
- **Protections**:
  - Bound Limits: Restricts maximum processed PDF page count to prevent CPU/memory exhaustion from decompression bombs.
  - Exception Isolation: PDF parsing exceptions (e.g. malformed headers, corrupt objects) are caught safely and converted to structured scan error messages rather than crashing the worker thread or application server.

## 4. Threat Intelligence & Secret Management
- **Status**: **PASS**
- **Component**: `app/config.py`, `app/services/threat_intel.py`
- **Protections**:
  - Credentials are loaded via environment variables (`VT_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`).
  - If threat intel API keys are absent or services are unreachable, the system returns `"status": "unavailable"` or `"status": "unknown"`.
  - Service unavailability is handled cleanly in the pipeline without zeroing out or falsifying the overall threat score.

## Summary Matrix

| Domain | Status | Severity | Notes |
| :--- | :--- | :--- | :--- |
| SSRF Defense | PASS | Critical (P0) | Multi-hop redirect validation and DNS resolution check active. |
| Path Traversal | PASS | Critical (P0) | In-memory stream handling prevents filesystem traversal. |
| PDF Decompression Bomb | PASS | High (P1) | Bounded page iteration and isolated PyMuPDF error handling. |
| Secret Management | PASS | High (P1) | Zero committed hardcoded API secrets; environment variable pattern enforced. |
| File Upload Limits | PASS | Medium (P2) | 10 MB limit and extension whitelist enforced. |
