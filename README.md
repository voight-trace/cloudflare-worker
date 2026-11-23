# Voight Trace — Cloudflare Worker Edge Collector

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)
[![license](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://voighttrace.com)

The **Voight Trace Cloudflare Worker Collector** operates directly on Cloudflare's global edge network (300+ cities), intercepting HTTP traffic and streaming anonymized telemetry to the Voight Trace Ingestion API asynchronously.

---

## ⚡ Zero Latency Impact
- **Non-blocking Execution:** The worker delegates all telemetry reporting via `ctx.waitUntil()`. The HTTP response from your origin is streamed back to the client immediately without waiting for the ingestion network request.
- **Fail-Safe Architecture:** If the Voight ingestion API or network connection is interrupted, the visitor's request is completely unaffected.

---

## 🚀 1-Minute Deployment Guide

### Step 1: Install Dependencies
```bash
cd collectors/cloudflare-worker
npm install
```

### Step 2: Configure Environment Variables
Edit `wrangler.toml` and set your `VOIGHT_TRACE_SITE_ID`:
```toml
[vars]
VOIGHT_TRACE_SITE_ID = "your-site-uuid"
VOIGHT_TRACE_INGEST_URL = "https://api.voighttrace.com/api/v1/ingestion/events"
```

### Step 3: Set Your Secret API Key
Run the following command to store your secret ingestion key in Cloudflare's encrypted vault:
```bash
npx wrangler secret put VOIGHT_TRACE_API_KEY
# Enter your secret key (e.g. vt_live_9a8f4c2e1b...) when prompted
```

### Step 4: Deploy to Cloudflare Edge
```bash
npx wrangler deploy
```

---

## 🌐 Deployment Modes

### Mode A: Cloudflare Route (Recommended)
Attach this worker to your existing domain in the Cloudflare Dashboard under **Workers Routes**:
- **Route:** `*yourdomain.com/*`
- **Zone:** `yourdomain.com`

### Mode B: Reverse Proxy Gateway
If your origin server is hosted outside Cloudflare DNS, configure `UPSTREAM_HOST` in `wrangler.toml`:
```toml
[vars]
UPSTREAM_HOST = "origin-backend.company.internal"
```
The worker will automatically forward requests to your origin and return responses to visitors.

---

## 🔒 Privacy & Security by Design (Edge Header & Credential Sanitization)

The **Cloudflare Worker Edge Collector** enforces a **strict Header Allowlist policy (`SAFE_AUDIT_HEADERS`)** directly at Cloudflare's global edge.

No private customer credentials, session tokens, or authentication secrets are ever captured or transmitted to the Voight Trace Ingestion API.

### 🚫 Prohibited Headers — NEVER Collected
Any header capable of carrying credentials or sensitive personal information is **strictly dropped at the edge**:
* ❌ `Authorization` / `Proxy-Authorization` (Bearer tokens, JWTs, Basic Auth)
* ❌ `Cookie` / `Set-Cookie` (User session identifiers, login cookies)
* ❌ `X-Api-Key` / `Api-Key` / `X-Auth-Token` (Customer private secrets)
* ❌ Passwords, custom authentication tokens, or POST/PUT request bodies

### ✅ Permitted Headers (`SAFE_AUDIT_HEADERS`)
Only standardized technical context headers required for AI agent traffic intelligence are extracted:
* **Core AI & Traffic Identification:** `user-agent` (identifies AI crawlers & LLM agents), `referer` (detects human referrals from ChatGPT, Claude, Perplexity), `host`, `origin`
* **Content Negotiation:** `accept`, `accept-encoding`, `accept-language`, `content-type`
* **Client Hints (Browser & Device Architecture):** `sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`, `sec-ch-ua-platform-version`, `sec-ch-ua-model`, `sec-ch-ua-arch`
* **Edge Request Metadata:** `sec-fetch-dest`, `sec-fetch-mode`, `sec-fetch-site`, `sec-fetch-user`

### 🔍 How to Audit in Code
For rapid security and compliance audits (LGPD, GDPR, SOC2):
* The allowlist constant `export const SAFE_AUDIT_HEADERS` and sanitizer `export function filterSafeHeaders(headers)` are located at the very top of [`worker.js`](./worker.js) (Lines 18 to 54).
* All telemetry dispatched via `ctx.waitUntil()` exclusively uses headers filtered by this function.
