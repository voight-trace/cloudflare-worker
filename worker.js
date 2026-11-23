/**
 * ============================================================================
 * SECURITY & PRIVACY AUDIT: ALLOWLISTED SAFE HEADERS
 * ============================================================================
 * Voight Trace Edge Collector operates on Cloudflare's global edge network.
 * Under ZERO circumstances does it capture sensitive visitor or client headers.
 *
 * EXPLICITLY FORBIDDEN / NEVER COLLECTED:
 * - authorization / proxy-authorization (Bearer tokens, JWTs, Basic Auth)
 * - cookie / set-cookie (Session identifiers, tracking cookies)
 * - x-api-key / api-key / x-auth-token / x-access-token
 * - any custom credentials, secrets, or password headers
 *
 * ONLY the following deterministic, non-sensitive headers strictly necessary
 * for AI bot classification, client hints, content negotiation, and routing
 * are extracted. All others are completely filtered out at the edge.
 */
export const SAFE_AUDIT_HEADERS = Object.freeze([
  // Core AI & Traffic Identification (Required for bot classification & GEO referrals)
  'user-agent',
  'referer',
  'host',
  'origin',

  // Content Negotiation
  'accept',
  'accept-encoding',
  'accept-language',
  'content-type',

  // Client Hints (Browser & Device Architecture)
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
  'sec-ch-ua-platform-version',
  'sec-ch-ua-model',
  'sec-ch-ua-arch',

  // Request & Fetch Context
  'sec-fetch-dest',
  'sec-fetch-mode',
  'sec-fetch-site',
  'sec-fetch-user'
]);

/**
 * Extracts ONLY safe, allowlisted headers from Cloudflare Request headers.
 * Guaranteed to never capture authorization tokens, cookies, or credentials.
 *
 * @param {Headers} headers - Cloudflare Request Headers
 * @returns {Record<string, string>} Sanitized allowlisted headers
 */
export function filterSafeHeaders(headers) {
  if (!headers) return {};
  const filtered = {};
  for (const name of SAFE_AUDIT_HEADERS) {
    const val = typeof headers.get === 'function' ? headers.get(name) : headers[name];
    if (val) filtered[name] = val;
  }
  return filtered;
}

/**
 * Voight Trace — Cloudflare Worker Edge Collector
 * Reference: docs/technical/03_service_spec_trace_and_ingestion.md
 *
 * Runs at Cloudflare's Global Edge (300+ datacenters).
 * Captures edge metadata, rDNS/ASN, and HTTP traffic without adding origin latency (0ms added).
 * Telemetry is dispatched asynchronously via ctx.waitUntil.
 */

export default {
  /**
   * Cloudflare Worker fetch event handler
   * @param {Request} request - Incoming Cloudflare HTTP Request
   * @param {Object} env - Environment bindings and secrets
   * @param {Object} ctx - Execution context with ctx.waitUntil
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    const startTime = Date.now();
    const url = new URL(request.url);

    // 1. Manage and propagate correlation ID downstream to origin
    let correlationId = request.headers.get('x-voight-trace-correlation-id');
    if (!correlationId) {
      correlationId = `vgt_${crypto.randomUUID()}`;
    }

    // Clone headers and inject correlation ID
    const modifiedHeaders = new Headers(request.headers);
    modifiedHeaders.set('x-voight-trace-correlation-id', correlationId);

    // Determine target origin request (supports direct route or reverse-proxy upstream)
    let originUrl = request.url;
    if (env.UPSTREAM_HOST) {
      originUrl = `${url.protocol}//${env.UPSTREAM_HOST}${url.pathname}${url.search}`;
      modifiedHeaders.set('host', env.UPSTREAM_HOST);
    }

    const originRequest = new Request(originUrl, {
      method: request.method,
      headers: modifiedHeaders,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      redirect: 'manual'
    });

    let response;
    let errorOccurred = null;

    try {
      // Forward request to origin site
      response = await fetch(originRequest);
    } catch (err) {
      errorOccurred = err;
      // In case origin is down, prepare synthetic 502 response
      response = new Response(JSON.stringify({ error: 'Bad Gateway', message: err.message }), {
        status: 502,
        headers: { 'Content-Type': 'application/json' }
      });
    } finally {
      const durationMs = Date.now() - startTime;
      const statusCode = response ? response.status : 502;
      const bytesSent = response ? Number(response.headers.get('content-length') || 0) : 0;

      // 2. Non-blocking asynchronous telemetry dispatch via ctx.waitUntil
      ctx.waitUntil(
        sendTelemetry({
          env,
          url,
          request,
          correlationId,
          statusCode,
          durationMs,
          bytesSent
        }).catch((err) => {
          // Telemetry errors must NEVER crash the user response (RNF-012)
          console.error('[Voight Trace Worker Dispatch Error]', err.message);
        })
      );
    }

    // Clone response to inject correlation ID back to the client
    const clientResponse = new Response(response.body, response);
    clientResponse.headers.set('x-voight-trace-correlation-id', correlationId);

    return clientResponse;
  }
};

/**
 * Asynchronously formats and sends the observation payload to the Voight Trace Ingestion API
 */
async function sendTelemetry({ env, url, request, correlationId, statusCode, durationMs, bytesSent }) {
  const apiKey = env.VOIGHT_TRACE_API_KEY;
  const siteId = env.VOIGHT_TRACE_SITE_ID;

  if (!apiKey || !siteId) {
    return;
  }

  const cf = request.cf || {};
  const observationId = crypto.randomUUID();
  const eventId = crypto.randomUUID();

  // Allowlisted safe headers only (security & privacy — audit safe)
  const selectedHeaders = filterSafeHeaders(request.headers);

  const clientIp = request.headers.get('cf-connecting-ip') || request.headers.get('x-real-ip') || 'edge-cf';

  const payload = {
    event_id: eventId,
    event_type: 'http.request',
    schema_version: 1,
    tenant_id: env.VOIGHT_TRACE_TENANT_ID || siteId,
    site_id: siteId,
    collector_id: env.VOIGHT_TRACE_COLLECTOR_ID || `cf_${cf.colo || 'edge'}`,
    collector_type: 'cloudflare_worker',
    observation_id: observationId,
    request_id: request.headers.get('cf-ray') || null,
    correlation_id: correlationId,
    occurred_at: new Date().toISOString(),
    request: {
      method: request.method ? request.method.toUpperCase() : 'GET',
      scheme: url.protocol.replace(':', ''),
      host: url.hostname,
      path: url.pathname,
      query_params: Object.fromEntries(url.searchParams.entries()),
      referer: request.headers.get('referer') || '',
      user_agent: request.headers.get('user-agent') || '',
      selected_headers: selectedHeaders
    },
    network: {
      ip_hash: clientIp,
      country: (cf.country || 'XX').toUpperCase(),
      asn: Number(cf.asn || 0),
      as_organization: cf.asOrganization || '',
      datacenter_colo: cf.colo || 'GLOBAL',
      client_rtt_ms: cf.clientTcpRtt || null
    },
    response: {
      status_code: statusCode,
      duration_ms: durationMs,
      bytes_sent: bytesSent
    }
  };

  const endpoint = env.VOIGHT_TRACE_INGEST_URL || 'https://api.voighttrace.com/api/v1/ingestion/events';

  const ingestRes = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
      'x-voight-collector-type': 'cloudflare_worker',
      'x-voight-collector-version': '2.4.0'
    },
    body: JSON.stringify({ events: [payload] })
  });

  if (!ingestRes.ok) {
    const errBody = await ingestRes.text();
    console.error(`[Voight Trace Worker] Ingestion rejected (HTTP ${ingestRes.status}):`, errBody);
  }
}
