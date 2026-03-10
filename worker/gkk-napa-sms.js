/**
 * G&KK NAPA SMS Marketing - Cloudflare Worker
 *
 * Manages B2B customer SMS subscriptions, campaigns, and Twilio integration.
 * Uses Cloudflare D1 for storage.
 *
 * Environment Variables Required:
 *   ADMIN_PASSWORD    - Admin panel password (same as careers)
 *   TWILIO_ACCOUNT_SID - Twilio account SID
 *   TWILIO_AUTH_TOKEN  - Twilio auth token
 *   TWILIO_PHONE_NUMBER - Twilio sending number (E.164)
 *   RESEND_API_KEY    - Resend API key for invitation emails
 *   FROM_EMAIL        - Sender email address
 *
 * D1 Binding:
 *   DB - gkk-napa-sms database
 */

// ─── CORS ────────────────────────────────────────────────────
const allowedOrigins = new Set([
  "https://gkk-napa.com",
  "https://www.gkk-napa.com",
  "https://gkk-napa.pages.dev",
]);

function isAllowedOrigin(origin) {
  if (!origin) return false;
  if (allowedOrigins.has(origin)) return true;
  if (origin.endsWith(".gkk-napa.pages.dev")) return true;
  if (origin.startsWith("http://localhost:") || origin.startsWith("http://127.0.0.1:")) return true;
  return false;
}

function getCorsHeaders(request) {
  const origin = request.headers.get("Origin");
  return {
    "Access-Control-Allow-Origin": isAllowedOrigin(origin) ? origin : "https://gkk-napa.com",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

// ─── Helpers ─────────────────────────────────────────────────
const VALID_STORES = ["danville", "cayuga", "rockville", "covington"];

const STORE_DISPLAY = {
  danville: "Danville, IL",
  cayuga: "Cayuga, IN",
  rockville: "Rockville, IN",
  covington: "Covington, IN",
};

function checkAdmin(request, env) {
  const auth = request.headers.get("Authorization");
  if (!auth || !env.ADMIN_PASSWORD) return false;
  return auth === `Bearer ${env.ADMIN_PASSWORD}`;
}

function jsonOk(corsHeaders, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function jsonError(corsHeaders, message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

/**
 * Normalize a phone number to E.164 format (+1XXXXXXXXXX).
 * Returns null if invalid.
 */
function normalizePhone(raw) {
  if (!raw) return null;
  const digits = raw.replace(/\D/g, "");
  if (digits.length === 10) return `+1${digits}`;
  if (digits.length === 11 && digits.startsWith("1")) return `+${digits}`;
  if (raw.startsWith("+1") && digits.length === 11) return `+${digits}`;
  return null;
}

// ─── Subscribe token helpers (HMAC-SHA256) ───────────────────
// Static per customer — same ID always produces the same token.
// Safe for QR codes on invoices, email links, etc.

async function generateSubscribeToken(customerId, env) {
  const payload = `subscribe:${customerId}`;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(env.ADMIN_PASSWORD),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  const hmac = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return btoa(`${customerId}:${hmac}`).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function verifySubscribeToken(token, env) {
  try {
    const decoded = atob(token.replace(/-/g, "+").replace(/_/g, "/"));
    const [customerId, hmac] = decoded.split(":");
    if (!customerId || !hmac) return null;

    const payload = `subscribe:${customerId}`;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw", enc.encode(env.ADMIN_PASSWORD),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
    const expected = btoa(String.fromCharCode(...new Uint8Array(sig)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    if (hmac !== expected) return null;

    return parseInt(customerId);
  } catch {
    return null;
  }
}

// ─── Short code helpers ──────────────────────────────────────
const SHORT_CODE_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789';

function generateShortCode() {
  const bytes = new Uint8Array(7);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => SHORT_CODE_CHARS[b % 36]).join('');
}

async function ensureShortCode(db, customerId) {
  const row = await db.prepare('SELECT short_code FROM customers WHERE id = ?').bind(customerId).first();
  if (row?.short_code) return row.short_code;
  const code = generateShortCode();
  await db.prepare('UPDATE customers SET short_code = ? WHERE id = ?').bind(code, customerId).run();
  return code;
}

const SMS_LOGO_URL = "https://gkk-napa.com/assets/sms-logo.png";
const WORKER_URL = "https://gkk-napa-sms.kellyraeknight78.workers.dev";

// ─── Video compression (Cloudinary on-the-fly transforms) ───
// Carrier MMS limit is ~600 KB. Cloudinary transforms compress server-side via URL params.
const MMS_VIDEO_TRANSFORMS = 'w_360,q_auto,br_250k,f_mp4,vc_h264';

function compressVideoUrl(mediaUrl) {
  if (!mediaUrl) return mediaUrl;
  // Only transform Cloudinary video URLs
  const match = mediaUrl.match(/^(https:\/\/res\.cloudinary\.com\/[^/]+\/video\/upload\/)(v\d+\/.+)$/);
  if (match) {
    return `${match[1]}${MMS_VIDEO_TRANSFORMS}/${match[2]}`;
  }
  return mediaUrl;
}

// ─── Media proxy (strips content-type params for Twilio) ────
function proxyMediaUrl(mediaUrl) {
  if (!mediaUrl) return null;
  // Compress Cloudinary videos to fit carrier MMS limits
  const compressed = compressVideoUrl(mediaUrl);
  // Proxy video URLs through our worker so Twilio gets clean content-type headers
  if (compressed.match(/\.(mp4|mov|webm|mpeg|3gp)(\?|$)/i) || compressed.includes('/video/')) {
    return `${WORKER_URL}/media/proxy?url=${encodeURIComponent(compressed)}`;
  }
  return compressed;
}

async function handleMediaProxy(url) {
  const targetUrl = url.searchParams.get('url');
  if (!targetUrl) return new Response("Missing url parameter", { status: 400 });

  // Only allow known media hosts to prevent open proxy abuse
  try {
    const parsed = new URL(targetUrl);
    const allowed = ['res.cloudinary.com', 'cloudinary.com', 'f002.backblazeb2.com'];
    if (!allowed.some(h => parsed.hostname.endsWith(h))) {
      return new Response("Host not allowed", { status: 403 });
    }
  } catch {
    return new Response("Invalid URL", { status: 400 });
  }

  const resp = await fetch(targetUrl);
  if (!resp.ok) return new Response("Upstream error", { status: resp.status });

  // Strip codec params: "video/mp4;codecs=avc1" → "video/mp4"
  let contentType = resp.headers.get('content-type') || 'application/octet-stream';
  contentType = contentType.split(';')[0].trim();

  return new Response(resp.body, {
    headers: {
      'Content-Type': contentType,
      'Content-Length': resp.headers.get('content-length') || '',
      'Cache-Control': 'public, max-age=86400',
    },
  });
}

// ─── Sale-Aware Promo Templates ─────────────────────────────
// Phase keys: upcoming, starts_today, reminder, ends_tomorrow, last_day
const SALE_TEMPLATES = {
  upcoming:       "Heads up! {{product_name}} goes on sale {{sale_start}} at {{store_label}}. {{sale_price_line}}\n\n{{cta_text}}: {{cta_url}}\n\nG&KK NAPA Auto Parts",
  starts_today:   "Starts today: {{product_name}} {{sale_price_line}} through {{sale_end}} at {{store_label}}.\n\n{{cta_text}}: {{cta_url}}\n\nG&KK NAPA Auto Parts",
  reminder:       "Reminder: {{product_name}} {{sale_price_line}} through {{sale_end}} at {{store_label}}.\n\n{{cta_text}}: {{cta_url}}\n\nG&KK NAPA",
  ends_tomorrow:  "Last chance! {{product_name}} sale ends tomorrow. {{sale_price_line}} at {{store_label}}.\n\n{{cta_text}}: {{cta_url}}\n\nG&KK NAPA",
  last_day:       "Final day: {{product_name}} {{sale_price_line}} today only at {{store_label}}.\n\n{{cta_text}}: {{cta_url}}\n\nG&KK NAPA",
};

// Sale-aware sequence presets — offsets relative to sale start/end
const SALE_SEQUENCE_PRESETS = {
  standard: [
    { anchor: "start", offsetDays: -2, phase: "upcoming",      label: "Upcoming" },
    { anchor: "start", offsetDays: 0,  phase: "starts_today",  label: "Starts Today" },
    { anchor: "mid",   offsetDays: 0,  phase: "reminder",      label: "Reminder" },
    { anchor: "end",   offsetDays: -1, phase: "ends_tomorrow", label: "Ends Tomorrow" },
    { anchor: "end",   offsetDays: 0,  phase: "last_day",      label: "Last Day" },
  ],
  light: [
    { anchor: "start", offsetDays: 0,  phase: "starts_today",  label: "Starts Today" },
    { anchor: "mid",   offsetDays: 0,  phase: "reminder",      label: "Reminder" },
    { anchor: "end",   offsetDays: 0,  phase: "last_day",      label: "Last Day" },
  ],
  "one-and-done": [
    { anchor: "start", offsetDays: 0,  phase: "starts_today",  label: "Starts Today" },
  ],
};

// CTA type definitions
const CTA_TYPES = {
  all_locations:  { text: "All Locations",  url: "https://gkk-napa.com/#locations" },
  get_directions: { text: "Get Directions", url: "https://gkk-napa.com/#locations" },
  call_store:     { text: "Call Us",        url: "https://gkk-napa.com/#locations" },
  view_product:   { text: "View Product",   url: null },
  shop_online:    { text: "Shop Online",    url: "https://www.napaonline.com/" },
};

const STORE_PHONES = {
  danville:   "(217) 446-9067",
  cayuga:     "(765) 492-3292",
  rockville:  "(765) 569-3100",
  covington:  "(765) 793-4693",
};

const STORE_MAP_URLS = {
  danville:   "https://maps.google.com/?q=G%26KK+NAPA+Danville+IL",
  cayuga:     "https://maps.google.com/?q=G%26KK+NAPA+Cayuga+IN",
  rockville:  "https://maps.google.com/?q=G%26KK+NAPA+Rockville+IN",
  covington:  "https://maps.google.com/?q=G%26KK+NAPA+Covington+IN",
};

// ─── Price Formatting Helper ────────────────────────────────
function formatPromoPrice(input) {
  if (!input || typeof input !== "string") return { formatted: null, warning: null };
  const cleaned = input.replace(/[$,\s]/g, "");
  const num = parseFloat(cleaned);
  if (isNaN(num)) return { formatted: null, warning: "Enter a valid price (example: 19.99)." };
  // Ambiguity check: no decimal and > 999
  if (!cleaned.includes(".") && num > 999) {
    return {
      formatted: "$" + num.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }),
      warning: `Price looks unusual. Did you mean $${(num / 100).toFixed(2)}? Enter decimals to avoid mistakes.`,
    };
  }
  return {
    formatted: "$" + num.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }),
    warning: null,
  };
}

function buildSalePriceLine(regularPrice, salePrice) {
  const reg = formatPromoPrice(regularPrice);
  const sale = formatPromoPrice(salePrice);
  if (!sale.formatted) return "";
  if (reg.formatted && reg.formatted !== sale.formatted) {
    return `was ${reg.formatted}, now ${sale.formatted}`;
  }
  return `now ${sale.formatted}`;
}

// ─── CTA Resolver ───────────────────────────────────────────
function resolvePromoCta({ ctaType, storeFilter, napaUrl, textOverride, destinationOverride }) {
  const def = CTA_TYPES[ctaType] || CTA_TYPES.all_locations;
  let ctaText = textOverride || def.text;
  let destinationUrl = destinationOverride || def.url || "";

  if (ctaType === "get_directions" && storeFilter && STORE_MAP_URLS[storeFilter]) {
    destinationUrl = destinationOverride || STORE_MAP_URLS[storeFilter];
  }
  if (ctaType === "call_store" && storeFilter && STORE_PHONES[storeFilter]) {
    destinationUrl = destinationOverride || `tel:${STORE_PHONES[storeFilter].replace(/\D/g, "")}`;
    if (!textOverride) ctaText = `Call ${STORE_PHONES[storeFilter]}`;
  }
  if (ctaType === "view_product") {
    destinationUrl = destinationOverride || napaUrl || "https://www.napaonline.com/";
  }

  return { ctaText, destinationUrl, imageBadgeText: textOverride || def.text };
}

// ─── Sale-Aware Template Renderer ───────────────────────────
function renderSaleTemplate(phase, vars) {
  const tpl = SALE_TEMPLATES[phase] || SALE_TEMPLATES.starts_today;
  let msg = tpl
    .replace(/\{\{product_name\}\}/g, vars.productName || "")
    .replace(/\{\{sale_price_line\}\}/g, vars.salePriceLine || "")
    .replace(/\{\{store_label\}\}/g, vars.storeLabel || "G&KK NAPA")
    .replace(/\{\{cta_text\}\}/g, vars.ctaText || "Shop Now")
    .replace(/\{\{cta_url\}\}/g, vars.ctaUrl || "")
    .replace(/\{\{sale_start\}\}/g, vars.saleStartDisplay || "")
    .replace(/\{\{sale_end\}\}/g, vars.saleEndDisplay || "");
  msg += "\n\nReply STOP to opt out.";
  return msg;
}

// ─── Cloudinary Image Composition ───────────────────────────
function buildPromoImageUrl(baseImageUrl, { headline, price, ctaText, dateLine }) {
  if (!baseImageUrl || !baseImageUrl.includes("res.cloudinary.com")) return baseImageUrl;
  const match = baseImageUrl.match(/^(https:\/\/res\.cloudinary\.com\/[^/]+\/image\/upload\/)(v\d+\/.+)$/);
  if (!match) return baseImageUrl;

  const overlays = [];
  if (headline) {
    const h = headline.length > 50 ? headline.slice(0, 47) + "..." : headline;
    const encoded = encodeURIComponent(h).replace(/%20/g, "%20");
    overlays.push(`l_text:Montserrat_48_bold:${encoded},co_white,g_north,y_40`);
  }
  if (price) {
    const encoded = encodeURIComponent(price).replace(/%20/g, "%20");
    overlays.push(`l_text:Montserrat_64_bold:${encoded},co_rgb:FFC836,g_center,y_30`);
  }
  if (ctaText) {
    const c = ctaText.length > 24 ? ctaText.slice(0, 21) + "..." : ctaText;
    const encoded = encodeURIComponent(c).replace(/%20/g, "%20");
    overlays.push(`l_text:Montserrat_36_bold:${encoded},co_rgb:111111,b_rgb:FFC836,bo_16px_solid_rgb:FFC836,g_south,y_40`);
  }
  if (dateLine) {
    const encoded = encodeURIComponent(dateLine).replace(/%20/g, "%20");
    overlays.push(`l_text:Montserrat_24_bold:${encoded},co_white,g_south_east,y_10,x_10`);
  }
  if (overlays.length === 0) return baseImageUrl;
  return `${match[1]}${overlays.join("/")}/${match[2]}`;
}

// ─── NAPA Product Scraper ───────────────────────────────────
function parseNapaMeta(html) {
  // Product image: prefer pdp-gallery-img data-src (actual product photo)
  // over og:image (which is often just the NAPA logo)
  let image = null;
  const galleryMatch = html.match(/class="[^"]*pdp-gallery-img[^"]*"\s+data-src="Product=([^"]+)"/i)
    || html.match(/data-src="Product=([^"]+)"\s+class="[^"]*pdp-gallery-img/i);
  if (galleryMatch) {
    const dataSrc = galleryMatch[1];
    image = `https://media.napaonline.com/is/image/${dataSrc}?preset=webproofxlarge`;
  }
  if (!image) {
    const ogMatch = html.match(/<meta\s+(?:property|name)="og:image"\s+content="([^"]+)"/i)
      || html.match(/<meta\s+content="([^"]+)"\s+(?:property|name)="og:image"/i);
    if (ogMatch && ogMatch[1] && !ogMatch[1].includes("logo") && !ogMatch[1].includes("icon")) {
      image = ogMatch[1];
      // Upgrade media.napaonline.com images to high-res preset if no preset already set
      if (image.includes("media.napaonline.com/is/image/") && !image.includes("preset=")) {
        image += (image.includes("?") ? "&" : "?") + "preset=webproofxlarge";
      }
    }
  }

  const titleMatch = html.match(/<meta\s+(?:property|name)="og:title"\s+content="([^"]+)"/i)
    || html.match(/<meta\s+content="([^"]+)"\s+(?:property|name)="og:title"/i);
  const title = titleMatch ? titleMatch[1] : null;

  // Try multiple price sources in order of reliability
  let price = null;

  // 1. JSON-LD structured data (most reliable)
  const ldJsonMatch = html.match(/<script\s+type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/gi);
  if (ldJsonMatch) {
    for (const block of ldJsonMatch) {
      const jsonStr = block.replace(/<\/?script[^>]*>/gi, '');
      try {
        const ld = JSON.parse(jsonStr);
        const p = ld?.offers?.price || ld?.offers?.[0]?.price || ld?.price;
        if (p) { price = String(p); break; }
      } catch (_) {}
    }
  }

  // 2. product:price meta tag
  if (!price) {
    const metaPrice = html.match(/<meta\s+(?:property|name)="product:price:amount"\s+content="([^"]+)"/i)
      || html.match(/<meta\s+content="([^"]+)"\s+(?:property|name)="product:price:amount"/i);
    if (metaPrice) price = metaPrice[1];
  }

  // 3. JSON in script tags (e.g. __INITIAL_STATE__, window data, etc.)
  if (!price) {
    const jsonPrice = html.match(/"(?:base_?price|price|salePrice|currentPrice|regularPrice)"\s*:\s*"?\$?([\d]+\.[\d]{2})"?/i);
    if (jsonPrice) price = jsonPrice[1];
  }

  // 4. data-price attribute
  if (!price) {
    const dataPrice = html.match(/data-price="([\d.]+)"/i);
    if (dataPrice) price = dataPrice[1];
  }

  // 5. NAPA-specific CSS classes
  if (!price) {
    const classPrice = html.match(/class="[^"]*geo-plp[^"]*price[^"]*"[^>]*>\s*\$?([\d,.]+)/i)
      || html.match(/class="[^"]*product[_-]?price[^"]*"[^>]*>\s*\$?([\d,.]+)/i)
      || html.match(/class="[^"]*price[^"]*"[^>]*>\s*\$?([\d,.]+)/i);
    if (classPrice) price = classPrice[1];
  }

  if (price) price = price.replace(/,/g, '');

  return { title, image, price };
}

async function fetchNapaMeta(url) {
  if (!url || !url.startsWith("https://www.napaonline.com/")) {
    throw new Error("URL must start with https://www.napaonline.com/");
  }
  const resp = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; GKK-NAPA-Bot/1.0)" },
    redirect: "follow",
  });
  if (!resp.ok) throw new Error(`NAPA fetch failed: HTTP ${resp.status}`);
  const html = await resp.text();
  return parseNapaMeta(html);
}

async function fetchNapaHtml(url) {
  const resp = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; GKK-NAPA-Bot/1.0)" },
    redirect: "follow",
  });
  if (!resp.ok) return null;
  return resp.text();
}

// ─── Sale-Aware Sequence Event Generator ────────────────────
function computeSaleEventDates(presetKey, saleStartDate, saleEndDate, defaultSendTime) {
  const preset = SALE_SEQUENCE_PRESETS[presetKey];
  if (!preset) throw new Error(`Unknown preset: ${presetKey}`);

  const saleStart = new Date(saleStartDate);
  const saleEnd = new Date(saleEndDate);
  const saleMid = new Date(saleStart.getTime() + (saleEnd.getTime() - saleStart.getTime()) / 2);

  // Parse time "09:00" → hours/minutes
  const [hours, minutes] = (defaultSendTime || "09:00").split(":").map(Number);

  return preset.map(step => {
    let baseDate;
    if (step.anchor === "start") baseDate = new Date(saleStart);
    else if (step.anchor === "end") baseDate = new Date(saleEnd);
    else baseDate = new Date(saleMid); // mid

    baseDate.setDate(baseDate.getDate() + step.offsetDays);
    baseDate.setHours(hours, minutes, 0, 0);

    return {
      phase: step.phase,
      label: step.label,
      sendAt: baseDate,
      sendAtIso: baseDate.toISOString(),
      isPast: baseDate < new Date(),
    };
  });
}

async function generateSaleSequenceEvents(db, campaignId, events, templateVars, mediaUrl, enabledPhases) {
  const now = new Date().toISOString();

  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    const enabled = !enabledPhases || enabledPhases.includes(ev.phase);
    const body = renderSaleTemplate(ev.phase, templateVars);

    let status;
    if (!enabled) status = "cancelled";
    else if (ev.isPast) status = "skipped";
    else status = "scheduled";

    await db.prepare(
      "INSERT INTO campaign_events (campaign_id, event_index, label, body, media_url, send_at, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(
      campaignId, i, ev.label, body,
      mediaUrl || null,
      ev.sendAtIso,
      status,
      now
    ).run();
  }
}

// ─── Cron: Process Scheduled Events ─────────────────────────
async function processScheduledEvents(env) {
  const now = new Date().toISOString();
  const events = await env.DB.prepare(
    "SELECT * FROM campaign_events WHERE status = 'scheduled' AND send_at <= ? ORDER BY send_at LIMIT 10"
  ).bind(now).all();

  if (events.results.length === 0) {
    console.log(JSON.stringify({ tag: "CRON_NO_EVENTS" }));
    return;
  }

  for (const event of events.results) {
    try {
      // Load parent campaign
      const campaign = await env.DB.prepare("SELECT * FROM campaigns WHERE id = ?").bind(event.campaign_id).first();
      if (!campaign) {
        await env.DB.prepare("UPDATE campaign_events SET status = 'cancelled' WHERE id = ?").bind(event.id).run();
        continue;
      }

      const promoMeta = campaign.promo_meta ? JSON.parse(campaign.promo_meta) : {};

      // Query eligible customers (same logic as handleSendCampaign)
      let customerSql = "SELECT * FROM customers WHERE sms_status = 'subscribed'";
      const binds = [];
      if (campaign.store_filter) { customerSql += " AND store = ?"; binds.push(campaign.store_filter); }
      if (promoMeta.priority_only) { customerSql += " AND is_priority = 1"; }

      const stmt = env.DB.prepare(customerSql);
      const customers = binds.length > 0 ? await stmt.bind(...binds).all() : await stmt.all();

      let sentCount = 0;
      let failedCount = 0;

      // Shorten URLs in the event body
      let finalBody = event.body;
      finalBody = await shortenUrlsInText(finalBody, env);

      for (const customer of customers.results) {
        const result = await sendSms(env, customer.phone, finalBody, event.media_url);

        await env.DB.prepare(
          "INSERT INTO messages (twilio_sid, customer_id, campaign_id, direction, body, status, error_code, created_at, updated_at) VALUES (?, ?, ?, 'outbound', ?, ?, ?, ?, ?)"
        ).bind(
          result.ok ? result.sid : null,
          customer.id,
          event.campaign_id,
          finalBody,
          result.ok ? (result.status || "queued") : "failed",
          result.ok ? null : (result.error || "send_failed"),
          now, now
        ).run();

        if (result.ok) sentCount++;
        else failedCount++;
      }

      // Email fallback for scheduled events
      if (promoMeta.email_fallback && env.RESEND_API_KEY) {
        let emailSql = "SELECT * FROM customers WHERE sms_status != 'subscribed' AND email IS NOT NULL AND email != ''";
        const emailBinds = [];
        if (campaign.store_filter) { emailSql += " AND store = ?"; emailBinds.push(campaign.store_filter); }
        if (promoMeta.priority_only) { emailSql += " AND is_priority = 1"; }

        const emailStmt = env.DB.prepare(emailSql);
        const emailCustomers = emailBinds.length > 0 ? await emailStmt.bind(...emailBinds).all() : await emailStmt.all();

        for (const customer of emailCustomers.results) {
          const greeting = customer.name ? customer.name.split(' ')[0] : "Valued Customer";
          const canSms = customer.phone && customer.line_type && customer.line_type !== 'landline';
          const displayPhone = canSms
            ? customer.phone.replace(/^\+1(\d{3})(\d{3})(\d{4})$/, '($1) $2-$3')
            : null;
          let subscribeUrl;
          if (canSms) {
            const shortCode = customer.short_code || await ensureShortCode(env.DB, customer.id);
            subscribeUrl = `https://gkk-napa.com/s/${shortCode}`;
          } else {
            subscribeUrl = 'https://gkk-napa.com/sms/subscribe';
          }
          const emailMedia = event.media_url && !event.media_url.match(/\.(mp4|mov|webm|mpeg|3gp)(\?|$)/i) ? event.media_url : null;
          const html = buildCampaignEmail(greeting, event.body, subscribeUrl, displayPhone, emailMedia);

          try {
            await fetch("https://api.resend.com/emails", {
              method: "POST",
              headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
              body: JSON.stringify({
                from: env.FROM_EMAIL,
                to: [customer.email],
                reply_to: env.REPLY_TO || "brian@danvillenapa.comcastbiz.net",
                subject: `${campaign.name} \u2014 G&KK NAPA`,
                html,
              }),
            });
          } catch (e) {
            console.error(JSON.stringify({ tag: "CRON_EMAIL_ERROR", customer_id: customer.id, error: e.message }));
          }
          await new Promise(r => setTimeout(r, 600));
        }
      }

      // Update event
      await env.DB.prepare(
        "UPDATE campaign_events SET status = 'sent', sent_count = ?, failed_count = ? WHERE id = ?"
      ).bind(sentCount, failedCount, event.id).run();

      console.log(JSON.stringify({ tag: "CRON_EVENT_SENT", event_id: event.id, campaign_id: event.campaign_id, sent: sentCount, failed: failedCount }));
    } catch (e) {
      console.error(JSON.stringify({ tag: "CRON_EVENT_ERROR", event_id: event.id, error: e.message }));
    }
  }
}

// ─── Twilio helpers ──────────────────────────────────────────
async function sendSms(env, to, body, mediaUrl) {
  const url = `https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_ACCOUNT_SID}/Messages.json`;
  const finalMediaUrl = proxyMediaUrl(mediaUrl);
  const params = new URLSearchParams({
    From: env.TWILIO_PHONE_NUMBER,
    To: to,
    StatusCallback: `${WORKER_URL}/twilio/status`,
  });
  if (body) params.set("Body", body);
  if (finalMediaUrl) params.set("MediaUrl", finalMediaUrl);

  const resp = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: "Basic " + btoa(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params.toString(),
  });

  const data = await resp.json();
  if (!resp.ok) {
    console.error(JSON.stringify({ tag: "TWILIO_SEND_ERROR", status: resp.status, error: data }));
    return { ok: false, error: data.message || "Twilio error" };
  }

  return { ok: true, sid: data.sid, status: data.status };
}

/**
 * Validate Twilio webhook signature (HMAC-SHA1).
 * See: https://www.twilio.com/docs/usage/security
 */
async function validateTwilioSignature(request, env, body) {
  const signature = request.headers.get("X-Twilio-Signature");
  if (!signature || !env.TWILIO_AUTH_TOKEN) return false;

  const url = new URL(request.url);
  const fullUrl = url.origin + url.pathname;

  // Sort form params alphabetically and concatenate
  const params = new URLSearchParams(body);
  const sorted = [...params.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  let dataString = fullUrl;
  for (const [key, val] of sorted) {
    dataString += key + val;
  }

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(env.TWILIO_AUTH_TOKEN),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(dataString));
  const expected = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));

  return signature === expected;
}

// ─── Main fetch + scheduled handler ──────────────────────────
export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(processScheduledEvents(env));
  },
  async fetch(request, env) {
    const corsHeaders = getCorsHeaders(request);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // ── Public: POST /subscribe ──
      if (request.method === "POST" && path === "/subscribe") {
        return handleSubscribe(request, env, corsHeaders);
      }

      // ── Admin: POST /admin/login ──
      if (request.method === "POST" && path === "/admin/login") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Invalid password.", 401);
        return jsonOk(corsHeaders, { success: true });
      }

      // ── Admin: GET /admin/stats ──
      if (request.method === "GET" && path === "/admin/stats") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleStats(env, corsHeaders);
      }

      // ── Admin: GET /admin/customers ──
      if (request.method === "GET" && path === "/admin/customers") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleListCustomers(url, env, corsHeaders);
      }

      // ── Admin: POST /admin/customers ──
      if (request.method === "POST" && path === "/admin/customers") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleAddCustomer(request, env, corsHeaders);
      }

      // ── Admin: PUT /admin/customers/:id ──
      if (request.method === "PUT" && path.match(/^\/admin\/customers\/\d+$/)) {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleUpdateCustomer(request, path, env, corsHeaders);
      }

      // ── Admin: DELETE /admin/customers/:id (supports both DELETE and POST to /delete) ──
      if (request.method === "DELETE" && path.match(/^\/admin\/customers\/\d+$/)) {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleDeleteCustomer(path.replace(/\/delete$/, ""), env, corsHeaders);
      }
      if (request.method === "POST" && path.match(/^\/admin\/customers\/\d+\/delete$/)) {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleDeleteCustomer(path.replace(/\/delete$/, ""), env, corsHeaders);
      }

      // ── Admin: POST /admin/import ──
      if (request.method === "POST" && path === "/admin/import") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleImport(request, env, corsHeaders);
      }

      // ── Admin: POST /admin/check-line-types ──
      if (request.method === "POST" && path === "/admin/check-line-types") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleCheckLineTypes(env, corsHeaders);
      }

      // ── Admin: POST /admin/invite ──
      if (request.method === "POST" && path === "/admin/invite") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleInvite(request, env, corsHeaders);
      }

      // ── Admin: POST /admin/send-test ──
      if (request.method === "POST" && path === "/admin/send-test") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleSendTest(request, env, corsHeaders);
      }

      // ── Admin: POST /admin/send-test-email ──
      if (request.method === "POST" && path === "/admin/send-test-email") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleSendTestEmail(request, env, corsHeaders);
      }

      // ── Admin: POST /admin/send ──
      if (request.method === "POST" && path === "/admin/send") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleSendCampaign(request, env, corsHeaders);
      }

      // ── Admin: POST /admin/campaign-compose ──
      if (request.method === "POST" && path === "/admin/campaign-compose") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleCampaignCompose(request, env, corsHeaders);
      }

      // ── Admin: GET /admin/media-library ──
      if (request.method === "GET" && path === "/admin/media-library") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleMediaLibrary(env, corsHeaders);
      }

      // ── Admin: POST /admin/media-library ──
      if (request.method === "POST" && path === "/admin/media-library") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleSaveToLibrary(request, env, corsHeaders);
      }

      // ── Admin: DELETE /admin/media-library/:id ──
      if (request.method === "DELETE" && path.match(/^\/admin\/media-library\/\d+$/)) {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        const id = path.split('/').pop();
        await env.DB.prepare("DELETE FROM media_library WHERE id = ?").bind(id).run();
        return jsonOk(corsHeaders, { ok: true });
      }

      // ── Admin: GET /admin/campaigns ──
      if (request.method === "GET" && path === "/admin/campaigns") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleListCampaigns(env, corsHeaders);
      }

      // ── Admin: GET /admin/campaigns/:id ──
      if (request.method === "GET" && path.match(/^\/admin\/campaigns\/\d+$/)) {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleGetCampaign(path, env, corsHeaders);
      }

      // ── Twilio: POST /twilio/status ──
      if (request.method === "POST" && path === "/twilio/status") {
        return handleTwilioStatus(request, env, corsHeaders);
      }

      // ── Twilio: POST /twilio/inbound ──
      if (request.method === "POST" && path === "/twilio/inbound") {
        return handleTwilioInbound(request, env, corsHeaders);
      }

      // ── Public: GET /quick-subscribe ──
      if (request.method === "GET" && path === "/quick-subscribe") {
        return handleQuickSubscribe(url, env);
      }

      // ── Public: GET /s/:code (short URL redirect) ──
      if (request.method === "GET" && path.match(/^\/s\/[a-z0-9]{7}$/)) {
        return handleShortUrl(path, env);
      }

      // ── Public: GET /l/:code (link shortener redirect) ──
      if (request.method === "GET" && path.match(/^\/l\/[a-z0-9]{7}$/)) {
        return handleLinkRedirect(path, env);
      }

      // ── Public: GET /media/proxy (clean content-type for Twilio) ──
      if (request.method === "GET" && path === "/media/proxy") {
        return handleMediaProxy(url);
      }
      if (request.method === "HEAD" && path === "/media/proxy") {
        return handleMediaProxy(url);
      }

      // ── Admin: POST /admin/promo/preview ──
      if (request.method === "POST" && path === "/admin/promo/preview") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handlePromoPreview(request, env, corsHeaders);
      }

      // ── Admin: POST /admin/promo/schedule ──
      if (request.method === "POST" && path === "/admin/promo/schedule") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handlePromoSchedule(request, env, corsHeaders);
      }

      // ── Admin: POST /admin/promo/cancel/:campaignId ──
      if (request.method === "POST" && path.match(/^\/admin\/promo\/cancel\/\d+$/)) {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handlePromoCancel(path, env, corsHeaders);
      }

      // ── Admin: GET /admin/promo/events ──
      if (request.method === "GET" && path === "/admin/promo/events") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handlePromoEvents(url, env, corsHeaders);
      }

      // ── Admin: POST /admin/napa-lookup ──
      if (request.method === "POST" && path === "/admin/napa-lookup") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleNapaLookup(request, env, corsHeaders);
      }

      // ── Admin: POST /admin/napa-part-search ──
      if (request.method === "POST" && path === "/admin/napa-part-search") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleNapaPartSearch(request, env, corsHeaders);
      }

      // ── Admin: GET /admin/promo/assets ──
      if (request.method === "GET" && path === "/admin/promo/assets") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleListPromoAssets(env, corsHeaders);
      }

      // ── Admin: POST /admin/promo/assets ──
      if (request.method === "POST" && path === "/admin/promo/assets") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleCreatePromoAsset(request, env, corsHeaders);
      }

      // ── Admin: GET /admin/dashboard ──
      if (request.method === "GET" && path === "/admin/dashboard") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleDashboard(env, corsHeaders);
      }

      // (text-invite removed — can't SMS customers without opt-in)

      // ── Admin: GET /admin/export ──
      if (request.method === "GET" && path === "/admin/export") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleExport(env, corsHeaders);
      }

      // ── Admin: POST /admin/generate-short-codes ──
      if (request.method === "POST" && path === "/admin/generate-short-codes") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleGenerateShortCodes(env, corsHeaders);
      }

      // ── Admin: POST /admin/remove-bg (Replicate AI background removal) ──
      if (request.method === "POST" && path === "/admin/remove-bg") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleRemoveBg(request, env, corsHeaders);
      }

      // ── Admin: GET /admin/proxy-image (CORS image proxy for canvas) ──
      // No auth required — URL domain is validated in handler, and CORS limits browser access
      if (request.method === "GET" && path === "/admin/proxy-image") {
        return handleProxyImage(request, corsHeaders);
      }

      // ── Admin: POST /admin/creative/preview ──
      if (request.method === "POST" && path === "/admin/creative/preview") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleCreativePreview(request, env, corsHeaders);
      }

      // ── Admin: POST /admin/creative/save ──
      if (request.method === "POST" && path === "/admin/creative/save") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleCreativeSave(request, env, corsHeaders);
      }

      // ── Admin: GET /admin/creative/:id ──
      if (request.method === "GET" && path.match(/^\/admin\/creative\/\d+$/)) {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleGetCreative(path, env, corsHeaders);
      }

      // ── Admin: GET /admin/creatives ──
      if (request.method === "GET" && path === "/admin/creatives") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleListCreatives(env, corsHeaders);
      }

      return jsonError(corsHeaders, "Not found", 404);
    } catch (err) {
      console.error(JSON.stringify({ tag: "UNHANDLED_ERROR", error: err.message, stack: err.stack }));
      return jsonError(corsHeaders, "Internal server error", 500);
    }
  },
};

// ═══════════════════════════════════════════════════════════════
// Phase 2: Subscribe Flow
// ═══════════════════════════════════════════════════════════════

async function handleSubscribe(request, env, corsHeaders) {
  const body = await request.json();
  const { phone: rawPhone, store, name } = body;

  if (!rawPhone) return jsonError(corsHeaders, "Phone number is required.", 400);

  const phone = normalizePhone(rawPhone);
  if (!phone) return jsonError(corsHeaders, "Invalid phone number. Please enter a 10-digit US number.", 400);

  if (store && !VALID_STORES.includes(store)) {
    return jsonError(corsHeaders, "Invalid store.", 400);
  }

  const now = new Date().toISOString();

  // Check if customer already exists
  const existing = await env.DB.prepare("SELECT id, sms_status FROM customers WHERE phone = ?").bind(phone).first();

  if (existing) {
    if (existing.sms_status === "subscribed") {
      return jsonOk(corsHeaders, { success: true, message: "You're already subscribed!" });
    }
    const nameUpdate = name ? ", name = ?" : "";
    const nameBinds = name ? [now, now, name, existing.id] : [now, now, existing.id];
    await env.DB.prepare(
      `UPDATE customers SET sms_status = 'subscribed', sms_consent_at = ?, updated_at = ?${nameUpdate} WHERE id = ?`
    ).bind(...nameBinds).run();
  } else {
    // New subscriber — create customer record
    const shortCode = generateShortCode();
    await env.DB.prepare(
      "INSERT INTO customers (phone, name, store, sms_status, sms_consent_at, source, short_code, created_at, updated_at) VALUES (?, ?, ?, 'subscribed', ?, 'web', ?, ?, ?)"
    ).bind(phone, name || null, store || null, now, shortCode, now, now).run();
  }

  // Send confirmation SMS
  if (env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN) {
    const confirmMsg =
      "Welcome to G&KK NAPA text updates! You'll receive order notifications, store hours, and occasional deals. Reply STOP to opt out, HELP for help. Msg&data rates may apply.";
    const result = await sendSms(env, phone, confirmMsg, SMS_LOGO_URL);

    // Log the confirmation message
    if (result.ok) {
      const customer = await env.DB.prepare("SELECT id FROM customers WHERE phone = ?").bind(phone).first();
      if (customer) {
        await env.DB.prepare(
          "INSERT INTO messages (twilio_sid, customer_id, direction, body, status, created_at, updated_at) VALUES (?, ?, 'outbound', ?, ?, ?, ?)"
        ).bind(result.sid, customer.id, confirmMsg, result.status || "queued", now, now).run();
      }
    }
  }

  return jsonOk(corsHeaders, { success: true, message: "You're subscribed! A confirmation text is on its way." });
}

// ═══════════════════════════════════════════════════════════════
// Quick Subscribe (one-click from invite email)
// ═══════════════════════════════════════════════════════════════

async function handleQuickSubscribe(url, env) {
  const token = url.searchParams.get("token");
  if (!token) {
    return Response.redirect("https://gkk-napa.com/sms/subscribe", 302);
  }

  const customerId = await verifySubscribeToken(token, env);
  if (!customerId) {
    return Response.redirect("https://gkk-napa.com/sms/subscribed?status=invalid", 302);
  }

  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) {
    return Response.redirect("https://gkk-napa.com/sms/subscribed?status=error", 302);
  }

  // Already subscribed — still show success
  if (customer.sms_status === "subscribed") {
    return Response.redirect("https://gkk-napa.com/sms/subscribed?status=already", 302);
  }

  // No phone number — can't send SMS, redirect to form
  if (!customer.phone) {
    return Response.redirect("https://gkk-napa.com/sms/subscribe", 302);
  }

  const now = new Date().toISOString();

  // Subscribe the customer
  await env.DB.prepare(
    "UPDATE customers SET sms_status = 'subscribed', sms_consent_at = ?, source = COALESCE(source, 'quick-subscribe'), updated_at = ? WHERE id = ?"
  ).bind(now, now, customer.id).run();

  // Send welcome SMS
  if (env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN) {
    const welcomeMsg =
      "Welcome to G&KK NAPA text updates! You'll receive order notifications, store hours, and occasional deals. Reply STOP to opt out, HELP for help. Msg&data rates may apply.";
    const result = await sendSms(env, customer.phone, welcomeMsg, SMS_LOGO_URL);
    if (result.ok) {
      await env.DB.prepare(
        "INSERT INTO messages (twilio_sid, customer_id, direction, body, status, created_at, updated_at) VALUES (?, ?, 'outbound', ?, ?, ?, ?)"
      ).bind(result.sid, customer.id, welcomeMsg, result.status || "queued", now, now).run();
    }
  }

  return Response.redirect("https://gkk-napa.com/sms/subscribed?status=success", 302);
}

// ═══════════════════════════════════════════════════════════════
// Admin: Stats
// ═══════════════════════════════════════════════════════════════

async function handleStats(env, corsHeaders) {
  const total = await env.DB.prepare("SELECT COUNT(*) as count FROM customers").first();
  const subscribed = await env.DB.prepare("SELECT COUNT(*) as count FROM customers WHERE sms_status = 'subscribed'").first();
  const invited = await env.DB.prepare("SELECT COUNT(*) as count FROM customers WHERE sms_status = 'invited'").first();
  const stopped = await env.DB.prepare("SELECT COUNT(*) as count FROM customers WHERE sms_status = 'stopped'").first();

  // Messages sent this month
  const monthStart = new Date();
  monthStart.setDate(1);
  monthStart.setHours(0, 0, 0, 0);
  const msgThisMonth = await env.DB.prepare(
    "SELECT COUNT(*) as count FROM messages WHERE direction = 'outbound' AND created_at >= ?"
  ).bind(monthStart.toISOString()).first();

  // Campaign count
  const campaignCount = await env.DB.prepare("SELECT COUNT(*) as count FROM campaigns").first();

  // Store breakdown
  const storeBreakdown = await env.DB.prepare(
    "SELECT store, COUNT(*) as count FROM customers GROUP BY store ORDER BY count DESC"
  ).all();

  return jsonOk(corsHeaders, {
    total_customers: total.count,
    subscribed: subscribed.count,
    invited: invited.count,
    stopped: stopped.count,
    none: total.count - subscribed.count - invited.count - stopped.count,
    messages_this_month: msgThisMonth.count,
    total_campaigns: campaignCount.count,
    store_breakdown: storeBreakdown.results,
  });
}

// ═══════════════════════════════════════════════════════════════
// Admin: Customer CRUD
// ═══════════════════════════════════════════════════════════════

async function handleListCustomers(url, env, corsHeaders) {
  const store = url.searchParams.get("store");
  const status = url.searchParams.get("status");
  const q = url.searchParams.get("q");
  const countOnly = url.searchParams.get("count_only");
  const priorityOnly = url.searchParams.get("priority_only");

  let sql = countOnly ? "SELECT COUNT(*) as count FROM customers WHERE 1=1" : "SELECT * FROM customers WHERE 1=1";
  const binds = [];

  if (store && VALID_STORES.includes(store)) {
    sql += " AND store = ?";
    binds.push(store);
  }
  if (status && ["none", "invited", "subscribed", "stopped"].includes(status)) {
    sql += " AND sms_status = ?";
    binds.push(status);
  }
  if (priorityOnly) {
    sql += " AND is_priority = 1";
  }
  if (q) {
    sql += " AND (name LIKE ? OR phone LIKE ? OR email LIKE ?)";
    const search = `%${q}%`;
    binds.push(search, search, search);
  }

  if (!countOnly) sql += " ORDER BY name ASC, created_at DESC";

  const stmt = env.DB.prepare(sql);
  const result = binds.length > 0 ? await stmt.bind(...binds).all() : await stmt.all();

  if (countOnly) return jsonOk(corsHeaders, { count: result.results[0].count });
  return jsonOk(corsHeaders, result.results);
}

async function handleAddCustomer(request, env, corsHeaders) {
  const body = await request.json();
  const { name, phone: rawPhone, email, store, notes, is_priority } = body;

  if (!rawPhone && !email) return jsonError(corsHeaders, "Phone number or email is required.", 400);

  let phone = null;
  if (rawPhone) {
    phone = normalizePhone(rawPhone);
    if (!phone) return jsonError(corsHeaders, "Invalid phone number.", 400);
  }

  if (store && !VALID_STORES.includes(store)) {
    return jsonError(corsHeaders, "Invalid store.", 400);
  }

  // Check for duplicate phone (only if phone provided)
  if (phone) {
    const existing = await env.DB.prepare("SELECT id FROM customers WHERE phone = ?").bind(phone).first();
    if (existing) return jsonError(corsHeaders, "A customer with this phone number already exists.", 409);
  }

  // If phone provided, look up line type and generate short code
  let lineType = null;
  let shortCode = null;
  if (phone) {
    lineType = await lookupLineType(phone, env);
    shortCode = generateShortCode();
  }

  const now = new Date().toISOString();
  const result = await env.DB.prepare(
    "INSERT INTO customers (phone, name, email, store, source, notes, line_type, short_code, is_priority, created_at, updated_at) VALUES (?, ?, ?, ?, 'admin', ?, ?, ?, ?, ?, ?)"
  ).bind(phone, name || null, email || null, store || null, notes || null, lineType, shortCode, is_priority ? 1 : 0, now, now).run();

  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(result.meta.last_row_id).first();
  return jsonOk(corsHeaders, customer, 201);
}

async function handleUpdateCustomer(request, path, env, corsHeaders) {
  const id = parseInt(path.split("/").pop());
  const body = await request.json();
  const { name, phone: rawPhone, email, store, notes, notes_append, sms_status, line_type, invite_sent_at, is_priority } = body;

  const existing = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(id).first();
  if (!existing) return jsonError(corsHeaders, "Customer not found.", 404);

  // Validate and normalize phone if provided
  let phone;
  if (rawPhone !== undefined) {
    if (rawPhone) {
      phone = normalizePhone(rawPhone);
      if (!phone) return jsonError(corsHeaders, "Invalid phone number.", 400);
      // Check for duplicate phone (exclude this customer)
      const dup = await env.DB.prepare("SELECT id FROM customers WHERE phone = ? AND id != ?").bind(phone, id).first();
      if (dup) return jsonError(corsHeaders, "A customer with this phone number already exists.", 409);
    } else {
      phone = null;
    }
  }

  if (store && !VALID_STORES.includes(store)) {
    return jsonError(corsHeaders, "Invalid store.", 400);
  }
  if (sms_status && !["none", "invited", "subscribed", "stopped"].includes(sms_status)) {
    return jsonError(corsHeaders, "Invalid status.", 400);
  }
  if (line_type && !["mobile", "landline", "voip"].includes(line_type)) {
    return jsonError(corsHeaders, "Invalid line type.", 400);
  }

  const now = new Date().toISOString();
  const updates = [];
  const binds = [];

  if (rawPhone !== undefined) {
    updates.push("phone = ?"); binds.push(phone);
    // If phone changed, re-lookup line type and ensure short code
    if (phone && phone !== existing.phone) {
      const newLineType = await lookupLineType(phone, env);
      updates.push("line_type = ?"); binds.push(newLineType);
      if (!existing.short_code) {
        updates.push("short_code = ?"); binds.push(generateShortCode());
      }
    }
    if (!phone) {
      updates.push("line_type = ?"); binds.push(null);
    }
  }
  if (name !== undefined) { updates.push("name = ?"); binds.push(name || null); }
  if (email !== undefined) { updates.push("email = ?"); binds.push(email || null); }
  if (store !== undefined) { updates.push("store = ?"); binds.push(store || null); }
  if (notes !== undefined) { updates.push("notes = ?"); binds.push(notes || null); }
  if (notes_append) {
    const current = existing.notes || '';
    updates.push("notes = ?");
    binds.push(current ? current + '\n' + notes_append : notes_append);
  }
  if (invite_sent_at !== undefined) { updates.push("invite_sent_at = ?"); binds.push(invite_sent_at); }
  if (line_type !== undefined) { updates.push("line_type = ?"); binds.push(line_type || null); }
  if (is_priority !== undefined) { updates.push("is_priority = ?"); binds.push(is_priority ? 1 : 0); }
  if (sms_status !== undefined) {
    updates.push("sms_status = ?");
    binds.push(sms_status);
    if (sms_status === "subscribed" && existing.sms_status !== "subscribed") {
      updates.push("sms_consent_at = ?");
      binds.push(now);
    }
    if (sms_status === "stopped" && existing.sms_status !== "stopped") {
      updates.push("sms_stop_at = ?");
      binds.push(now);
    }
  }

  if (updates.length === 0) return jsonError(corsHeaders, "No fields to update.", 400);

  updates.push("updated_at = ?");
  binds.push(now);
  binds.push(id);

  await env.DB.prepare(`UPDATE customers SET ${updates.join(", ")} WHERE id = ?`).bind(...binds).run();

  const updated = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(id).first();
  return jsonOk(corsHeaders, updated);
}

async function handleDeleteCustomer(path, env, corsHeaders) {
  const id = parseInt(path.split("/").pop());
  const existing = await env.DB.prepare("SELECT id FROM customers WHERE id = ?").bind(id).first();
  if (!existing) return jsonError(corsHeaders, "Customer not found.", 404);

  // Delete associated messages first (foreign key constraint)
  await env.DB.prepare("DELETE FROM messages WHERE customer_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM customers WHERE id = ?").bind(id).run();
  return jsonOk(corsHeaders, { success: true });
}

// ═══════════════════════════════════════════════════════════════
// Admin: Twilio Lookup — check line types
// ═══════════════════════════════════════════════════════════════

async function lookupLineType(phone, env) {
  const resp = await fetch(
    `https://lookups.twilio.com/v2/PhoneNumbers/${encodeURIComponent(phone)}?Fields=line_type_intelligence`,
    { headers: { Authorization: "Basic " + btoa(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`) } }
  );
  if (!resp.ok) return null;
  const data = await resp.json();
  return data.line_type_intelligence?.type || null;
}

async function handleCheckLineTypes(env, corsHeaders) {
  // Ensure column exists (safe to run multiple times)
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS _migration_check (id INTEGER PRIMARY KEY)"
  ).run();
  try {
    await env.DB.prepare("ALTER TABLE customers ADD COLUMN line_type TEXT").run();
  } catch { /* column already exists */ }

  // Fetch customers with phone but no line_type
  const customers = await env.DB.prepare(
    "SELECT id, phone FROM customers WHERE phone IS NOT NULL AND phone != '' AND line_type IS NULL"
  ).all();

  if (customers.results.length === 0) {
    return jsonOk(corsHeaders, { checked: 0, message: "All customers already have line_type set." });
  }

  const now = new Date().toISOString();
  let checked = 0;
  let errors = 0;

  for (const c of customers.results) {
    const lineType = await lookupLineType(c.phone, env);
    if (lineType) {
      await env.DB.prepare(
        "UPDATE customers SET line_type = ?, updated_at = ? WHERE id = ?"
      ).bind(lineType, now, c.id).run();
      checked++;
    } else {
      errors++;
    }
  }

  return jsonOk(corsHeaders, { checked, errors, total: customers.results.length });
}

// ═══════════════════════════════════════════════════════════════
// Short URL redirect
// ═══════════════════════════════════════════════════════════════

async function handleShortUrl(path, env) {
  const code = path.split('/').pop();
  const customer = await env.DB.prepare('SELECT id FROM customers WHERE short_code = ?').bind(code).first();
  if (!customer) {
    return Response.redirect('https://gkk-napa.com/sms/subscribe', 302);
  }
  const token = await generateSubscribeToken(customer.id, env);
  return Response.redirect(
    `https://gkk-napa-sms.kellyraeknight78.workers.dev/quick-subscribe?token=${token}`, 302
  );
}

// ═══════════════════════════════════════════════════════════════
// Link Shortener
// ═══════════════════════════════════════════════════════════════

async function handleLinkRedirect(path, env) {
  const code = path.split('/').pop();
  const row = await env.DB.prepare('SELECT url FROM short_links WHERE code = ?').bind(code).first();
  if (!row) {
    return new Response("Not found", { status: 404 });
  }
  return Response.redirect(row.url, 302);
}

/**
 * Find URLs in text and replace them with gkk-napa.com/l/ short links.
 * Reuses existing short links for the same URL.
 */
async function shortenUrlsInText(text, env) {
  const urlRegex = /https?:\/\/[^\s)>\]]+/gi;
  const urls = text.match(urlRegex);
  if (!urls) return text;

  // Ensure short_links table exists
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS short_links (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL, url TEXT NOT NULL, created_at TEXT NOT NULL)"
  ).run();

  let result = text;
  for (const url of urls) {
    // Skip if already a gkk-napa.com short link
    if (url.includes('gkk-napa.com/l/') || url.includes('gkk-napa.com/s/')) continue;

    // Check if we already have a short link for this URL
    let row = await env.DB.prepare('SELECT code FROM short_links WHERE url = ?').bind(url).first();
    if (!row) {
      const code = generateShortCode();
      const now = new Date().toISOString();
      await env.DB.prepare('INSERT INTO short_links (code, url, created_at) VALUES (?, ?, ?)').bind(code, url, now).run();
      row = { code };
    }

    result = result.replace(url, `https://gkk-napa.com/l/${row.code}`);
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════
// Admin: Dashboard (alerts + actions + KPIs)
// ═══════════════════════════════════════════════════════════════

async function handleDashboard(env, corsHeaders) {
  const weekAgo = new Date(Date.now() - 7 * 86400000).toISOString();
  const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString();

  // Run all queries in parallel
  const [
    readyToInvite,
    emailOnlyNoMobile,
    staleInvites,
    needsOutreach,
    mobileNoEmail,
    newFromStripe,
    newFromWeb,
    newFromQuickSubscribe,
    totalInvited,
    convertedFromInvite,
    sourceBreakdown,
    recentActivity,
    totalSubscribed,
    totalCustomers,
    failedSms,
    failedSmsDetails,
    priorityCustomers,
    messagesThisMonth,
  ] = await Promise.all([
    // Ready to invite: has email + mobile + status none
    env.DB.prepare(
      "SELECT COUNT(*) as count FROM customers WHERE email IS NOT NULL AND email != '' AND line_type = 'mobile' AND sms_status = 'none'"
    ).first(),
    // Email only, no mobile
    env.DB.prepare(
      "SELECT COUNT(*) as count FROM customers WHERE email IS NOT NULL AND email != '' AND (phone IS NULL OR phone = '' OR line_type = 'landline') AND sms_status IN ('none', 'invited')"
    ).first(),
    // Stale invites (30+ days, not subscribed)
    env.DB.prepare(
      "SELECT COUNT(*) as count FROM customers WHERE sms_status = 'invited' AND invite_sent_at < ?"
    ).bind(thirtyDaysAgo).first(),
    // Needs outreach: no email AND (no mobile phone or landline only)
    env.DB.prepare(
      "SELECT COUNT(*) as count FROM customers WHERE (email IS NULL OR email = '') AND (phone IS NULL OR phone = '' OR line_type = 'landline')"
    ).first(),
    // Mobile but no email
    env.DB.prepare(
      "SELECT COUNT(*) as count FROM customers WHERE (email IS NULL OR email = '') AND line_type = 'mobile' AND sms_status IN ('none', 'invited')"
    ).first(),
    // New from Stripe this week
    env.DB.prepare(
      "SELECT COUNT(*) as count FROM customers WHERE source = 'payment' AND created_at >= ?"
    ).bind(weekAgo).first(),
    // New from web form this week
    env.DB.prepare(
      "SELECT COUNT(*) as count FROM customers WHERE source = 'web' AND created_at >= ?"
    ).bind(weekAgo).first(),
    // New from quick-subscribe this week
    env.DB.prepare(
      "SELECT COUNT(*) as count FROM customers WHERE source = 'quick-subscribe' AND created_at >= ?"
    ).bind(weekAgo).first(),
    // Total ever invited
    env.DB.prepare("SELECT COUNT(*) as count FROM customers WHERE invite_sent_at IS NOT NULL").first(),
    // Converted from invite (subscribed + was invited)
    env.DB.prepare("SELECT COUNT(*) as count FROM customers WHERE sms_status = 'subscribed' AND invite_sent_at IS NOT NULL").first(),
    // Source breakdown
    env.DB.prepare("SELECT COALESCE(source, 'unknown') as source, COUNT(*) as count FROM customers GROUP BY source ORDER BY count DESC").all(),
    // Recent activity (new/changed this week)
    env.DB.prepare(
      "SELECT id, name, phone, email, store, sms_status, source, line_type, created_at, updated_at FROM customers WHERE created_at >= ? ORDER BY created_at DESC LIMIT 15"
    ).bind(weekAgo).all(),
    // Total subscribed
    env.DB.prepare("SELECT COUNT(*) as count FROM customers WHERE sms_status = 'subscribed'").first(),
    // Total customers
    env.DB.prepare("SELECT COUNT(*) as count FROM customers").first(),
    // Failed SMS this week
    env.DB.prepare(
      "SELECT COUNT(*) as count FROM messages WHERE direction = 'outbound' AND status IN ('failed', 'undelivered') AND created_at >= ?"
    ).bind(weekAgo).first(),
    // Failed SMS details this week
    env.DB.prepare(
      `SELECT m.id, m.body, m.status, m.error_code, m.created_at,
              c.name, c.phone, c.id as customer_id
       FROM messages m JOIN customers c ON m.customer_id = c.id
       WHERE m.direction='outbound' AND m.status IN ('failed','undelivered') AND m.created_at >= ?
       ORDER BY m.created_at DESC LIMIT 20`
    ).bind(weekAgo).all(),
    // Priority customers count
    env.DB.prepare("SELECT COUNT(*) as count FROM customers WHERE is_priority = 1").first(),
    // Messages sent this month
    env.DB.prepare(
      "SELECT COUNT(*) as count FROM messages WHERE direction = 'outbound' AND created_at >= ?"
    ).bind(new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString()).first(),
  ]);

  const conversionRate = totalInvited.count > 0
    ? Math.round((convertedFromInvite.count / totalInvited.count) * 1000) / 10
    : 0;

  return jsonOk(corsHeaders, {
    alerts: {
      failed_sms: failedSms.count,
      failed_sms_details: failedSmsDetails.results,
      new_from_stripe: newFromStripe.count,
      new_from_web: newFromWeb.count,
      new_from_quick_subscribe: newFromQuickSubscribe.count,
    },
    actions: {
      ready_to_invite: readyToInvite.count,
      email_only_no_mobile: emailOnlyNoMobile.count,
      stale_invites: staleInvites.count,
      needs_outreach: needsOutreach.count,
      mobile_no_email: mobileNoEmail.count,
    },
    kpis: {
      total_customers: totalCustomers.count,
      total_subscribed: totalSubscribed.count,
      conversion_rate: conversionRate,
      total_invited: totalInvited.count,
      converted_from_invite: convertedFromInvite.count,
      priority_customers: priorityCustomers.count,
      messages_this_month: messagesThisMonth.count,
    },
    source_breakdown: sourceBreakdown.results,
    recent_activity: recentActivity.results,
  });
}

// (handleTextInvite removed — can't SMS customers without prior opt-in)

// ═══════════════════════════════════════════════════════════════
// Admin: CSV Export
// ═══════════════════════════════════════════════════════════════

async function handleExport(env, corsHeaders) {
  const customers = await env.DB.prepare(
    "SELECT id, name, phone, email, store, sms_status, line_type, source, short_code, is_priority, notes, invite_sent_at, sms_consent_at, created_at FROM customers ORDER BY name ASC"
  ).all();

  const headers = ['ID', 'Name', 'Phone', 'Email', 'Store', 'Status', 'Line Type', 'Source', 'Short Code', 'Subscribe URL', 'Priority', 'Notes', 'Invite Sent', 'Subscribed At', 'Created'];

  const csvEscape = (val) => {
    if (val === null || val === undefined) return '';
    const str = String(val);
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return '"' + str.replace(/"/g, '""') + '"';
    }
    return str;
  };

  let csv = headers.join(',') + '\n';
  for (const c of customers.results) {
    const subscribeUrl = c.short_code ? `https://gkk-napa.com/s/${c.short_code}` : '';
    csv += [
      c.id, csvEscape(c.name), c.phone, csvEscape(c.email),
      STORE_DISPLAY[c.store] || c.store || '', c.sms_status, c.line_type || '',
      c.source || '', c.short_code || '', subscribeUrl, c.is_priority ? 'Yes' : '',
      csvEscape(c.notes), c.invite_sent_at || '', c.sms_consent_at || '', c.created_at
    ].join(',') + '\n';
  }

  return new Response(csv, {
    headers: {
      ...corsHeaders,
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="gkk-napa-customers-${new Date().toISOString().slice(0,10)}.csv"`,
    },
  });
}

// ═══════════════════════════════════════════════════════════════
// Admin: Generate Short Codes (batch)
// ═══════════════════════════════════════════════════════════════

async function handleGenerateShortCodes(env, corsHeaders) {
  const customers = await env.DB.prepare(
    "SELECT id FROM customers WHERE short_code IS NULL"
  ).all();

  let generated = 0;
  for (const c of customers.results) {
    await ensureShortCode(env.DB, c.id);
    generated++;
  }

  return jsonOk(corsHeaders, { generated, message: `${generated} short codes created.` });
}

// ═══════════════════════════════════════════════════════════════
// Admin: Bulk Import
// ═══════════════════════════════════════════════════════════════

async function handleImport(request, env, corsHeaders) {
  const body = await request.json();
  const { customers } = body;

  if (!Array.isArray(customers) || customers.length === 0) {
    return jsonError(corsHeaders, "Expected an array of customers.", 400);
  }

  const now = new Date().toISOString();
  let imported = 0;
  let skipped = 0;
  const errors = [];

  for (const c of customers) {
    const phone = normalizePhone(c.phone);
    if (!phone) {
      errors.push(`Invalid phone: ${c.phone} (${c.name || "unknown"})`);
      skipped++;
      continue;
    }

    // Skip duplicates
    const existing = await env.DB.prepare("SELECT id FROM customers WHERE phone = ?").bind(phone).first();
    if (existing) {
      skipped++;
      continue;
    }

    const store = c.store && VALID_STORES.includes(c.store) ? c.store : null;

    await env.DB.prepare(
      "INSERT INTO customers (phone, name, email, store, sms_status, source, notes, created_at, updated_at) VALUES (?, ?, ?, ?, 'none', 'import', ?, ?, ?)"
    ).bind(phone, c.name || null, c.email || null, store, c.notes || null, now, now).run();
    imported++;
  }

  return jsonOk(corsHeaders, { imported, skipped, errors });
}

// ═══════════════════════════════════════════════════════════════
// Phase 3: Email Invitations
// ═══════════════════════════════════════════════════════════════

async function handleInvite(request, env, corsHeaders) {
  const body = await request.json();
  const { customer_ids, subject: customSubject, intro: customIntro, bullets: customBullets } = body;

  if (!Array.isArray(customer_ids) || customer_ids.length === 0) {
    return jsonError(corsHeaders, "Expected an array of customer IDs.", 400);
  }

  if (!env.RESEND_API_KEY) {
    return jsonError(corsHeaders, "Email sending is not configured.", 500);
  }

  // Fetch eligible customers (have email, status is none or invited)
  const placeholders = customer_ids.map(() => "?").join(",");
  const customers = await env.DB.prepare(
    `SELECT * FROM customers WHERE id IN (${placeholders}) AND email IS NOT NULL AND email != '' AND sms_status IN ('none', 'invited')`
  ).bind(...customer_ids).all();

  if (customers.results.length === 0) {
    return jsonError(corsHeaders, "No eligible customers found (need email + status none/invited).", 400);
  }

  const emailSubject = customSubject || "Subscribe to text updates from G&KK NAPA";
  const emailIntro = customIntro || null;
  const emailBullets = Array.isArray(customBullets) && customBullets.length > 0 ? customBullets : null;

  const now = new Date().toISOString();
  let sent = 0;
  let failed = 0;

  for (const customer of customers.results) {
    const storeName = customer.store ? (STORE_DISPLAY[customer.store] || customer.store) : "your local store";
    const greeting = customer.name || "Valued Customer";

    // Format phone for display: +12174419077 → (217) 441-9077
    // Any non-landline phone can receive SMS (mobile, voip, nonfixedvoip, etc.)
    const canSms = customer.phone && customer.line_type && customer.line_type !== 'landline';
    const displayPhone = canSms
      ? customer.phone.replace(/^\+1(\d{3})(\d{3})(\d{4})$/, '($1) $2-$3')
      : null;

    // Non-landline customers get personalized one-click link; others get the subscribe form
    let subscribeUrl;
    if (canSms) {
      const shortCode = customer.short_code || await ensureShortCode(env.DB, customer.id);
      subscribeUrl = `https://gkk-napa.com/s/${shortCode}`;
    } else {
      subscribeUrl = 'https://gkk-napa.com/sms/subscribe';
    }

    const html = buildInviteEmail(greeting, storeName, subscribeUrl, displayPhone, emailIntro, emailBullets);

    try {
      const resp = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: env.FROM_EMAIL,
          to: [customer.email],
          reply_to: env.REPLY_TO || "brian@danvillenapa.comcastbiz.net",
          subject: emailSubject,
          html,
        }),
      });

      if (resp.ok) {
        await env.DB.prepare(
          "UPDATE customers SET sms_status = 'invited', invite_sent_at = ?, updated_at = ? WHERE id = ?"
        ).bind(now, now, customer.id).run();
        sent++;
      } else {
        const err = await resp.text();
        console.error(JSON.stringify({ tag: "INVITE_EMAIL_ERROR", customer_id: customer.id, error: err }));
        failed++;
      }
    } catch (e) {
      console.error(JSON.stringify({ tag: "INVITE_EMAIL_EXCEPTION", customer_id: customer.id, error: e.message }));
      failed++;
    }

    // Rate limit: 600ms between sends (Resend free tier = 2/sec)
    await new Promise(r => setTimeout(r, 600));
  }

  return jsonOk(corsHeaders, { sent, failed, total_eligible: customers.results.length });
}

function buildInviteEmail(firstName, storeName, subscribeUrl, displayPhone, customIntro, customBullets) {
  const intro = customIntro || `We're excited to offer text updates from ${storeName}! Subscribe to get:`;
  const bullets = customBullets || ["Order-ready notifications", "Store hours & closure alerts", "Occasional deals & promotions"];
  const bulletRows = bullets.map(b => `  <tr><td style="padding:6px 0;font-size:15px;color:#333;">&#10003;&nbsp;&nbsp;${escHtml(b)}</td></tr>`).join("\n");

  const phoneNote = displayPhone
    ? `<tr><td style="padding:0 24px 16px;">
<p style="margin:0;font-size:14px;color:#333;line-height:1.5;text-align:center;">
  Texts will be sent to <strong>${displayPhone}</strong><br>
  <span style="font-size:12px;color:#888;">Not a mobile number? <a href="https://gkk-napa.com/sms/subscribe" style="color:#0A0094;">Subscribe with a different number</a></span>
</p>
</td></tr>`
    : '';

  const buttonText = displayPhone ? 'Subscribe with One Click' : 'Subscribe Now';

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f3f4f6;font-family:Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f3f4f6;">
<tr><td align="center" style="padding:24px 16px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);">

<!-- NAPA Header -->
<tr><td style="background-color:#0A0094;">
<img src="https://gkk-napa.com/assets/pay-email-logo.png" alt="NAPA Auto Parts" height="75" style="display:block;height:75px;width:auto;">
<div style="color:#ffffff;font-size:13px;padding:0 0 10px 12px;">G&amp;KK Store Updates</div>
</td></tr>

<!-- Body -->
<tr><td style="padding:32px 24px 16px;">
<h1 style="margin:0 0 16px;font-size:22px;color:#111;font-weight:700;">Hi ${firstName},</h1>
<p style="margin:0 0 16px;font-size:16px;color:#333;line-height:1.6;">
  ${escHtml(intro)}
</p>
<table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 24px;">
${bulletRows}
</table>
</td></tr>

<!-- Phone number notice -->
${phoneNote}

<!-- One-Click Subscribe Button -->
<tr><td align="center" style="padding:0 24px 16px;">
<a href="${subscribeUrl}" target="_blank"
   style="display:inline-block;background-color:#FFC836;color:#0A0094;font-size:16px;font-weight:700;text-decoration:none;padding:14px 32px;border-radius:8px;text-transform:uppercase;letter-spacing:0.5px;">
  ${buttonText}
</a>
</td></tr>

<!-- Consent note -->
<tr><td style="padding:0 24px 24px;">
<p style="margin:0;font-size:12px;color:#888;line-height:1.5;text-align:center;">
  By clicking subscribe, you agree to receive SMS messages from G&amp;KK NAPA Auto Parts
  about order updates, store hours/closures, and occasional promotions.
  Message frequency varies. Msg &amp; data rates may apply.
  Consent is not a condition of purchase. Reply STOP to opt out, HELP for help.
  See <a href="https://gkk-napa.com/privacy.html" style="color:#0A0094;">Privacy Policy</a> and
  <a href="https://gkk-napa.com/terms.html" style="color:#0A0094;">Terms of Service</a>.
</p>
</td></tr>

<!-- Footer -->
<tr><td style="background-color:#f9fafb;padding:16px 24px;border-top:1px solid #e5e7eb;">
<p style="margin:0;font-size:12px;color:#888;text-align:center;">G&amp;KK NAPA Auto Parts &middot; <a href="https://gkk-napa.com" style="color:#0A0094;">gkk-napa.com</a></p>
</td></tr>

</table>
</td></tr>
</table>
</body></html>`;
}

function buildCampaignEmail(greeting, messageBody, subscribeUrl, displayPhone, mediaUrl) {
  const phoneNote = displayPhone
    ? `<tr><td style="padding:0 24px 16px;">
<p style="margin:0;font-size:14px;color:#333;line-height:1.5;text-align:center;">
  Want texts instead? Get updates faster via SMS!<br>
  Texts will be sent to <strong>${displayPhone}</strong>
</p>
</td></tr>`
    : '';

  const mediaSection = mediaUrl
    ? `<tr><td align="center" style="padding:0 24px 16px;">
<img src="${mediaUrl}" alt="" style="max-width:100%;border-radius:8px;" />
</td></tr>`
    : '';

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f3f4f6;font-family:Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f3f4f6;">
<tr><td align="center" style="padding:24px 16px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);">

<!-- NAPA Header -->
<tr><td style="background-color:#0A0094;">
<img src="https://gkk-napa.com/assets/pay-email-logo.png" alt="NAPA Auto Parts" height="75" style="display:block;height:75px;width:auto;">
<div style="color:#ffffff;font-size:13px;padding:0 0 10px 12px;">G&amp;KK Store Updates</div>
</td></tr>

<!-- Body -->
<tr><td style="padding:32px 24px 16px;">
<h1 style="margin:0 0 16px;font-size:22px;color:#111;font-weight:700;">Hi ${escHtml(greeting)},</h1>
<p style="margin:0 0 16px;font-size:16px;color:#333;line-height:1.6;white-space:pre-wrap;">${escHtml(messageBody)}</p>
</td></tr>

${mediaSection}

<!-- Subscribe CTA -->
${phoneNote}
<tr><td align="center" style="padding:0 24px 24px;">
<a href="${subscribeUrl}" target="_blank"
   style="display:inline-block;background-color:#FFC836;color:#0A0094;font-size:14px;font-weight:700;text-decoration:none;padding:12px 28px;border-radius:8px;text-transform:uppercase;letter-spacing:0.5px;">
  Subscribe to Text Updates
</a>
</td></tr>

<!-- Footer -->
<tr><td style="background-color:#f9fafb;padding:16px 24px;border-top:1px solid #e5e7eb;">
<p style="margin:0;font-size:12px;color:#888;text-align:center;">G&amp;KK NAPA Auto Parts &middot; <a href="https://gkk-napa.com" style="color:#0A0094;">gkk-napa.com</a></p>
</td></tr>

</table>
</td></tr>
</table>
</body></html>`;
}

// ═══════════════════════════════════════════════════════════════
// Phase 4: SMS Campaign Sending
// ═══════════════════════════════════════════════════════════════

async function handleSendTest(request, env, corsHeaders) {
  const body = await request.json();
  const { body: messageBody, phone: rawPhone, image_url } = body;

  const hasBody = messageBody && messageBody.trim();
  const mediaUrl = image_url || null;

  if (!hasBody && !mediaUrl) return jsonError(corsHeaders, "Message body or media is required.", 400);
  if (!rawPhone) return jsonError(corsHeaders, "Phone number is required.", 400);

  const phone = normalizePhone(rawPhone);
  if (!phone) return jsonError(corsHeaders, "Invalid phone number.", 400);

  // Auto-shorten any URLs in the message body
  let finalBody = hasBody ? messageBody.trim() : "";
  if (finalBody) {
    finalBody = await shortenUrlsInText(finalBody, env);
    finalBody += "\n\nReply STOP to opt out.";
  }

  const result = await sendSms(env, phone, finalBody, mediaUrl);

  if (!result.ok) {
    return jsonError(corsHeaders, `Twilio error: ${result.error}`, 502);
  }

  return jsonOk(corsHeaders, { success: true, sid: result.sid });
}

async function handleSendTestEmail(request, env, corsHeaders) {
  if (!env.RESEND_API_KEY) return jsonError(corsHeaders, "Email sending is not configured (RESEND_API_KEY).", 500);

  const body = await request.json();
  const { email, subject, sms_text, image_url } = body;

  if (!email || !email.includes("@")) return jsonError(corsHeaders, "Valid email address is required.", 400);
  if (!sms_text && !image_url) return jsonError(corsHeaders, "Message text or image is required.", 400);

  const emailSubject = subject || "G&KK NAPA — Creative Studio Test";

  // Build a simple HTML email showing the MMS image + SMS text
  const imgHtml = image_url
    ? `<tr><td style="padding:0 0 16px;"><img src="${escHtml(image_url)}" alt="MMS Preview" style="max-width:100%;border-radius:8px;" /></td></tr>`
    : "";
  const textHtml = sms_text
    ? `<tr><td style="padding:16px;background:#f5f5f5;border-radius:8px;font-family:monospace;font-size:14px;line-height:1.5;white-space:pre-wrap;color:#333;">${escHtml(sms_text)}</td></tr>`
    : "";

  const html = `<!DOCTYPE html><html><body style="margin:0;padding:0;font-family:Arial,Helvetica,sans-serif;background:#fff;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:540px;margin:0 auto;padding:24px;">
  <tr><td style="padding:0 0 12px;font-size:12px;color:#888;text-transform:uppercase;letter-spacing:1px;">Creative Studio Test Preview</td></tr>
  ${imgHtml}
  ${textHtml ? `<tr><td style="padding:12px 0 4px;font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px;">SMS Text</td></tr>` + textHtml : ""}
  <tr><td style="padding:24px 0 0;font-size:11px;color:#aaa;text-align:center;">Sent from G&amp;KK NAPA Creative Studio</td></tr>
</table></body></html>`;

  try {
    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: env.FROM_EMAIL,
        to: [email],
        reply_to: env.REPLY_TO || "brian@danvillenapa.comcastbiz.net",
        subject: emailSubject,
        html,
      }),
    });

    if (!resp.ok) {
      const err = await resp.text();
      console.error(JSON.stringify({ tag: "TEST_EMAIL_ERROR", error: err }));
      return jsonError(corsHeaders, `Email send failed: ${err}`, 502);
    }

    return jsonOk(corsHeaders, { success: true });
  } catch (e) {
    console.error(JSON.stringify({ tag: "TEST_EMAIL_EXCEPTION", error: e.message }));
    return jsonError(corsHeaders, `Email error: ${e.message}`, 500);
  }
}

async function handleSendCampaign(request, env, corsHeaders) {
  const body = await request.json();
  const { name, body: messageBody, store, image_url, email_fallback, priority_only } = body;

  const hasBody = messageBody && messageBody.trim();
  const mediaUrl = image_url || null;

  if (!name || !name.trim()) return jsonError(corsHeaders, "Campaign name is required.", 400);
  if (!hasBody && !mediaUrl) return jsonError(corsHeaders, "Message body or media is required.", 400);
  if (hasBody && messageBody.length > 1500) return jsonError(corsHeaders, "Message body must be under 1500 characters.", 400);

  if (store && !VALID_STORES.includes(store)) {
    return jsonError(corsHeaders, "Invalid store filter.", 400);
  }

  // Auto-shorten URLs and append opt-out footer
  let fullMessage = hasBody ? messageBody.trim() : "";
  if (fullMessage) {
    fullMessage = await shortenUrlsInText(fullMessage, env);
    fullMessage += "\n\nReply STOP to opt out.";
  }

  // Query subscribed customers
  let customerSql = "SELECT * FROM customers WHERE sms_status = 'subscribed'";
  const binds = [];
  if (store) {
    customerSql += " AND store = ?";
    binds.push(store);
  }
  if (priority_only) {
    customerSql += " AND is_priority = 1";
  }

  const stmt = env.DB.prepare(customerSql);
  const customers = binds.length > 0 ? await stmt.bind(...binds).all() : await stmt.all();

  if (customers.results.length === 0) {
    return jsonError(corsHeaders, "No subscribed customers found for the selected filter.", 400);
  }

  // Create campaign record
  const now = new Date().toISOString();
  const campaignResult = await env.DB.prepare(
    "INSERT INTO campaigns (name, body, store_filter, recipient_count, created_at) VALUES (?, ?, ?, ?, ?)"
  ).bind(name.trim(), messageBody.trim(), store || null, customers.results.length, now).run();

  const campaignId = campaignResult.meta.last_row_id;

  // Send to each subscriber
  let sentCount = 0;
  let failedCount = 0;

  for (const customer of customers.results) {
    const result = await sendSms(env, customer.phone, fullMessage, mediaUrl);

    await env.DB.prepare(
      "INSERT INTO messages (twilio_sid, customer_id, campaign_id, direction, body, status, error_code, created_at, updated_at) VALUES (?, ?, ?, 'outbound', ?, ?, ?, ?, ?)"
    ).bind(
      result.ok ? result.sid : null,
      customer.id,
      campaignId,
      fullMessage,
      result.ok ? (result.status || "queued") : "failed",
      result.ok ? null : (result.error || "send_failed"),
      now,
      now
    ).run();

    if (result.ok) sentCount++;
    else failedCount++;
  }

  // ── Email fallback: email non-subscribed customers ──
  let emailSent = 0;
  let emailFailed = 0;

  if (email_fallback && env.RESEND_API_KEY) {
    let emailSql = "SELECT * FROM customers WHERE sms_status != 'subscribed' AND email IS NOT NULL AND email != ''";
    const emailBinds = [];
    if (store) { emailSql += " AND store = ?"; emailBinds.push(store); }
    if (priority_only) { emailSql += " AND is_priority = 1"; }

    const emailStmt = env.DB.prepare(emailSql);
    const emailCustomers = emailBinds.length > 0 ? await emailStmt.bind(...emailBinds).all() : await emailStmt.all();

    for (const customer of emailCustomers.results) {
      const greeting = customer.name ? customer.name.split(' ')[0] : "Valued Customer";
      const canSms = customer.phone && customer.line_type && customer.line_type !== 'landline';
      const displayPhone = canSms
        ? customer.phone.replace(/^\+1(\d{3})(\d{3})(\d{4})$/, '($1) $2-$3')
        : null;

      let subscribeUrl;
      if (canSms) {
        const shortCode = customer.short_code || await ensureShortCode(env.DB, customer.id);
        subscribeUrl = `https://gkk-napa.com/s/${shortCode}`;
      } else {
        subscribeUrl = 'https://gkk-napa.com/sms/subscribe';
      }

      // Only include image media in email (not video)
      const emailMedia = mediaUrl && !mediaUrl.match(/\.(mp4|mov|webm|mpeg|3gp)(\?|$)/i) && !mediaUrl.includes('/video/')
        ? mediaUrl : null;

      const html = buildCampaignEmail(greeting, messageBody.trim(), subscribeUrl, displayPhone, emailMedia);

      try {
        const resp = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${env.RESEND_API_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            from: env.FROM_EMAIL,
            to: [customer.email],
            reply_to: env.REPLY_TO || "brian@danvillenapa.comcastbiz.net",
            subject: `${name.trim()} — G&KK NAPA`,
            html,
          }),
        });

        if (resp.ok) {
          emailSent++;
        } else {
          const err = await resp.text();
          console.error(JSON.stringify({ tag: "CAMPAIGN_EMAIL_ERROR", customer_id: customer.id, error: err }));
          emailFailed++;
        }
      } catch (e) {
        console.error(JSON.stringify({ tag: "CAMPAIGN_EMAIL_EXCEPTION", customer_id: customer.id, error: e.message }));
        emailFailed++;
      }

      // Rate limit: 600ms between sends (Resend free tier = 2/sec)
      await new Promise(r => setTimeout(r, 600));
    }
  }

  // Update campaign counters
  await env.DB.prepare(
    "UPDATE campaigns SET sent_count = ?, failed_count = ?, email_count = ?, email_failed_count = ? WHERE id = ?"
  ).bind(sentCount, failedCount, emailSent, emailFailed, campaignId).run();

  return jsonOk(corsHeaders, {
    campaign_id: campaignId,
    recipient_count: customers.results.length,
    sent: sentCount,
    failed: failedCount,
    email_sent: emailSent,
    email_failed: emailFailed,
  });
}

// ─── Campaign Composer ─────────────────────────────────────────
async function handleCampaignCompose(request, env, corsHeaders) {
  const body = await request.json();
  const { name, store, priority_only, email_fallback, messages } = body;

  if (!name || !name.trim()) return jsonError(corsHeaders, "Campaign name is required.", 400);
  if (!messages || !Array.isArray(messages) || messages.length === 0) return jsonError(corsHeaders, "At least one message is required.", 400);
  if (store && !VALID_STORES.includes(store)) return jsonError(corsHeaders, "Invalid store filter.", 400);

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    const hasBody = msg.body && msg.body.trim();
    if (!hasBody && !msg.media_url) return jsonError(corsHeaders, `Message ${i + 1} needs text or media.`, 400);
    if (hasBody && msg.body.length > 1500) return jsonError(corsHeaders, `Message ${i + 1} exceeds 1500 characters.`, 400);
    if (i > 0 && !msg.send_at) return jsonError(corsHeaders, `Message ${i + 1} must have a scheduled time.`, 400);
  }

  const now = new Date().toISOString();
  const promoMeta = JSON.stringify({ priority_only: !!priority_only, email_fallback: !!email_fallback });
  const firstMsg = messages[0];

  const campaignResult = await env.DB.prepare(
    "INSERT INTO campaigns (name, body, store_filter, recipient_count, promo_type, promo_meta, media_url, created_at) VALUES (?, ?, ?, 0, 'compose', ?, ?, ?)"
  ).bind(name.trim(), firstMsg.body || "", store || null, promoMeta, firstMsg.media_url || null, now).run();
  const campaignId = campaignResult.meta.last_row_id;

  const eventIds = [];
  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    const sendAt = (i === 0 && msg.send_now) ? now : msg.send_at;
    const status = (i === 0 && msg.send_now) ? "sending" : "scheduled";
    const evResult = await env.DB.prepare(
      "INSERT INTO campaign_events (campaign_id, event_index, label, body, media_url, send_at, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(campaignId, i, `Message ${i + 1}`, msg.body || "", msg.media_url || null, sendAt, status, now).run();
    eventIds.push(evResult.meta.last_row_id);
  }

  let sentCount = 0, failedCount = 0, emailSent = 0, emailFailed = 0;

  if (firstMsg.send_now) {
    let customerSql = "SELECT * FROM customers WHERE sms_status = 'subscribed'";
    const binds = [];
    if (store) { customerSql += " AND store = ?"; binds.push(store); }
    if (priority_only) { customerSql += " AND is_priority = 1"; }
    const stmt = env.DB.prepare(customerSql);
    const customers = binds.length > 0 ? await stmt.bind(...binds).all() : await stmt.all();

    let fullMessage = firstMsg.body ? firstMsg.body.trim() : "";
    if (fullMessage) {
      fullMessage = await shortenUrlsInText(fullMessage, env);
      fullMessage += "\n\nReply STOP to opt out.";
    }

    for (const customer of customers.results) {
      const result = await sendSms(env, customer.phone, fullMessage, firstMsg.media_url);
      await env.DB.prepare(
        "INSERT INTO messages (twilio_sid, customer_id, campaign_id, direction, body, status, error_code, created_at, updated_at) VALUES (?, ?, ?, 'outbound', ?, ?, ?, ?, ?)"
      ).bind(result.ok ? result.sid : null, customer.id, campaignId, fullMessage, result.ok ? (result.status || "queued") : "failed", result.ok ? null : (result.error || "send_failed"), now, now).run();
      if (result.ok) sentCount++; else failedCount++;
    }

    if (email_fallback && env.RESEND_API_KEY) {
      let emailSql = "SELECT * FROM customers WHERE sms_status != 'subscribed' AND email IS NOT NULL AND email != ''";
      const emailBinds = [];
      if (store) { emailSql += " AND store = ?"; emailBinds.push(store); }
      if (priority_only) { emailSql += " AND is_priority = 1"; }
      const emailCustomers = emailBinds.length > 0 ? await env.DB.prepare(emailSql).bind(...emailBinds).all() : await env.DB.prepare(emailSql).all();

      for (const customer of emailCustomers.results) {
        const greeting = customer.name ? customer.name.split(' ')[0] : "Valued Customer";
        const canSms = customer.phone && customer.line_type && customer.line_type !== 'landline';
        const displayPhone = canSms ? customer.phone.replace(/^\+1(\d{3})(\d{3})(\d{4})$/, '($1) $2-$3') : null;
        const shortCode = canSms ? (customer.short_code || await ensureShortCode(env.DB, customer.id)) : null;
        const subscribeUrl = canSms ? `https://gkk-napa.com/s/${shortCode}` : 'https://gkk-napa.com/sms/subscribe';
        const emailMedia = firstMsg.media_url && !firstMsg.media_url.match(/\.(mp4|mov|webm|mpeg|3gp)(\?|$)/i) ? firstMsg.media_url : null;
        const html = buildCampaignEmail(greeting, firstMsg.body || "", subscribeUrl, displayPhone, emailMedia);
        try {
          const resp = await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
            body: JSON.stringify({ from: env.FROM_EMAIL, to: [customer.email], reply_to: env.REPLY_TO || "brian@danvillenapa.comcastbiz.net", subject: `${name.trim()} \u2014 G&KK NAPA`, html }),
          });
          if (resp.ok) emailSent++; else emailFailed++;
        } catch (e) { emailFailed++; }
        await new Promise(r => setTimeout(r, 600));
      }
    }

    await env.DB.prepare("UPDATE campaign_events SET status = 'sent', sent_count = ?, failed_count = ? WHERE id = ?").bind(sentCount, failedCount, eventIds[0]).run();
    await env.DB.prepare("UPDATE campaigns SET recipient_count = ?, sent_count = ?, failed_count = ?, email_count = ?, email_failed_count = ? WHERE id = ?").bind(sentCount + failedCount, sentCount, failedCount, emailSent, emailFailed, campaignId).run();
  }

  return jsonOk(corsHeaders, {
    campaign_id: campaignId,
    events: eventIds.length,
    sent: sentCount,
    failed: failedCount,
    email_sent: emailSent,
    scheduled: messages.filter((m, i) => i > 0 || !m.send_now).length,
  });
}

// ═══════════════════════════════════════════════════════════════
// Twilio Webhooks
// ═══════════════════════════════════════════════════════════════

async function handleTwilioStatus(request, env, corsHeaders) {
  const rawBody = await request.text();

  // Validate Twilio signature
  const valid = await validateTwilioSignature(request, env, rawBody);
  if (!valid) {
    console.error(JSON.stringify({ tag: "TWILIO_STATUS_INVALID_SIG" }));
    return new Response("Forbidden", { status: 403 });
  }

  const params = new URLSearchParams(rawBody);
  const messageSid = params.get("MessageSid");
  const messageStatus = params.get("MessageStatus");
  const errorCode = params.get("ErrorCode");

  if (!messageSid || !messageStatus) {
    return new Response("OK", { status: 200 });
  }

  const now = new Date().toISOString();

  // Update message status
  await env.DB.prepare(
    "UPDATE messages SET status = ?, error_code = ?, updated_at = ? WHERE twilio_sid = ?"
  ).bind(messageStatus, errorCode || null, now, messageSid).run();

  // Update campaign delivered/failed counts
  const msg = await env.DB.prepare(
    "SELECT campaign_id FROM messages WHERE twilio_sid = ?"
  ).bind(messageSid).first();

  if (msg && msg.campaign_id) {
    if (messageStatus === "delivered") {
      await env.DB.prepare(
        "UPDATE campaigns SET delivered_count = delivered_count + 1 WHERE id = ?"
      ).bind(msg.campaign_id).run();
    } else if (messageStatus === "failed" || messageStatus === "undelivered") {
      await env.DB.prepare(
        "UPDATE campaigns SET failed_count = failed_count + 1 WHERE id = ?"
      ).bind(msg.campaign_id).run();
    }
  }

  console.log(JSON.stringify({ tag: "TWILIO_STATUS", sid: messageSid, status: messageStatus, errorCode }));
  return new Response("OK", { status: 200 });
}

async function handleTwilioInbound(request, env, corsHeaders) {
  const rawBody = await request.text();

  // Validate Twilio signature
  const valid = await validateTwilioSignature(request, env, rawBody);
  if (!valid) {
    console.error(JSON.stringify({ tag: "TWILIO_INBOUND_INVALID_SIG" }));
    return new Response("Forbidden", { status: 403 });
  }

  const params = new URLSearchParams(rawBody);
  const from = params.get("From");
  const body = (params.get("Body") || "").trim();
  const messageSid = params.get("MessageSid");

  if (!from || !body) {
    return twimlResponse("");
  }

  const phone = normalizePhone(from);
  const now = new Date().toISOString();
  const upperBody = body.toUpperCase();

  // Find customer
  const customer = phone
    ? await env.DB.prepare("SELECT * FROM customers WHERE phone = ?").bind(phone).first()
    : null;

  // Log inbound message
  if (customer) {
    await env.DB.prepare(
      "INSERT INTO messages (twilio_sid, customer_id, direction, body, status, created_at, updated_at) VALUES (?, ?, 'inbound', ?, 'delivered', ?, ?)"
    ).bind(messageSid || null, customer.id, body, now, now).run();
  }

  // Handle STOP
  if (upperBody === "STOP" || upperBody === "STOPALL" || upperBody === "UNSUBSCRIBE" || upperBody === "CANCEL" || upperBody === "END" || upperBody === "QUIT") {
    if (customer) {
      await env.DB.prepare(
        "UPDATE customers SET sms_status = 'stopped', sms_stop_at = ?, updated_at = ? WHERE id = ?"
      ).bind(now, now, customer.id).run();
    }
    console.log(JSON.stringify({ tag: "SMS_STOP", phone: from }));
    // Twilio auto-handles STOP responses, so return empty TwiML
    return twimlResponse("");
  }

  // Handle START / UNSTOP
  if (upperBody === "START" || upperBody === "YES" || upperBody === "UNSTOP") {
    if (customer) {
      await env.DB.prepare(
        "UPDATE customers SET sms_status = 'subscribed', sms_consent_at = ?, sms_stop_at = NULL, updated_at = ? WHERE id = ?"
      ).bind(now, now, customer.id).run();
    }
    console.log(JSON.stringify({ tag: "SMS_START", phone: from }));
    return twimlResponse("You've been re-subscribed to G&KK NAPA text updates. Reply STOP to opt out.");
  }

  // Handle HELP
  if (upperBody === "HELP" || upperBody === "INFO") {
    console.log(JSON.stringify({ tag: "SMS_HELP", phone: from }));
    return twimlResponse("G&KK NAPA Auto Parts SMS. For help call (217) 446-9067 or email napa.danville@comcastbiz.net. Reply STOP to opt out.");
  }

  // Handle NAPA keyword opt-in
  if (upperBody === "NAPA") {
    if (customer && customer.sms_status === "subscribed") {
      console.log(JSON.stringify({ tag: "SMS_NAPA_ALREADY", phone: from }));
      return twimlResponse("You're already subscribed to G&KK NAPA Savings Alerts! Reply STOP to opt out.");
    }

    const now2 = new Date().toISOString();
    if (customer) {
      // Existing customer, not subscribed — re-subscribe
      await env.DB.prepare(
        "UPDATE customers SET sms_status = 'subscribed', sms_consent_at = ?, sms_stop_at = NULL, source = COALESCE(source, 'text-in'), updated_at = ? WHERE id = ?"
      ).bind(now2, now2, customer.id).run();
      console.log(JSON.stringify({ tag: "SMS_NAPA_RESUBSCRIBE", phone: from }));
    } else {
      // Brand new subscriber
      const shortCode = generateShortCode();
      await env.DB.prepare(
        "INSERT INTO customers (phone, sms_status, sms_consent_at, source, short_code, created_at, updated_at) VALUES (?, 'subscribed', ?, 'text-in', ?, ?, ?)"
      ).bind(phone, now2, shortCode, now2, now2).run();
      console.log(JSON.stringify({ tag: "SMS_NAPA_NEW", phone: from }));
    }

    // Send welcome SMS with logo image (same as web subscribe flow)
    const welcomeMsg = "Welcome to G&KK NAPA Savings Alerts! You'll receive exclusive deals from your local G&KK NAPA stores. Reply STOP to opt out, HELP for help. Msg&data rates may apply.";
    const result = await sendSms(env, phone, welcomeMsg, SMS_LOGO_URL);

    // Log the welcome message
    const newCustomer = customer || await env.DB.prepare("SELECT id FROM customers WHERE phone = ?").bind(phone).first();
    if (result.ok && newCustomer) {
      await env.DB.prepare(
        "INSERT INTO messages (twilio_sid, customer_id, direction, body, status, created_at, updated_at) VALUES (?, ?, 'outbound', ?, ?, ?, ?)"
      ).bind(result.sid, newCustomer.id, welcomeMsg, result.status || "queued", now2, now2).run();
    }

    return twimlResponse("");
  }

  // Unknown inbound — log it
  console.log(JSON.stringify({ tag: "SMS_INBOUND", phone: from, body }));
  return twimlResponse("");
}

function twimlResponse(message) {
  const body = message
    ? `<?xml version="1.0" encoding="UTF-8"?><Response><Message>${escXml(message)}</Message></Response>`
    : `<?xml version="1.0" encoding="UTF-8"?><Response></Response>`;
  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "text/xml" },
  });
}

function escXml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function escHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ═══════════════════════════════════════════════════════════════
// Admin: Promo Endpoints
// ═══════════════════════════════════════════════════════════════

async function handlePromoPreview(request, env, corsHeaders) {
  const body = await request.json();
  const { offer, media, cta, sequence, storeFilter } = body;

  if (!offer || !offer.productName) return jsonError(corsHeaders, "Product name is required.", 400);
  if (!offer.salePrice) return jsonError(corsHeaders, "Sale price is required.", 400);
  if (!offer.saleStartDate || !offer.saleEndDate) return jsonError(corsHeaders, "Sale start and end dates are required.", 400);

  // Price formatting
  const salePriceFmt = formatPromoPrice(offer.salePrice);
  const regularPriceFmt = offer.regularPrice ? formatPromoPrice(offer.regularPrice) : { formatted: null, warning: null };
  const warnings = [];
  if (salePriceFmt.warning) warnings.push(salePriceFmt.warning);
  if (regularPriceFmt.warning) warnings.push(regularPriceFmt.warning);
  if (!salePriceFmt.formatted) return jsonError(corsHeaders, "Enter a valid sale price.", 400);

  const salePriceLine = buildSalePriceLine(offer.regularPrice, offer.salePrice);

  // CTA resolution
  const resolvedCta = resolvePromoCta({
    ctaType: cta?.type || "all_locations",
    storeFilter: storeFilter || null,
    napaUrl: media?.napaUrl || null,
    textOverride: cta?.textOverride || null,
    destinationOverride: cta?.destinationOverride || null,
  });

  // Shorten the CTA URL for preview
  let shortCtaUrl = resolvedCta.destinationUrl;
  if (shortCtaUrl && shortCtaUrl.startsWith("http") && !shortCtaUrl.includes("gkk-napa.com/l/")) {
    const shortened = await shortenUrlsInText(shortCtaUrl, env);
    shortCtaUrl = shortened;
  }

  const storeLabel = storeFilter ? (STORE_DISPLAY[storeFilter] || storeFilter) : "G&KK NAPA";
  const saleStartDisplay = new Date(offer.saleStartDate).toLocaleDateString("en-US", { month: "short", day: "numeric" });
  const saleEndDisplay = new Date(offer.saleEndDate).toLocaleDateString("en-US", { month: "short", day: "numeric" });

  const templateVars = {
    productName: offer.productName,
    salePriceLine,
    storeLabel,
    ctaText: resolvedCta.ctaText,
    ctaUrl: shortCtaUrl,
    saleStartDisplay,
    saleEndDisplay,
  };

  // Generate messages for all phases
  const presetKey = sequence?.preset || "one-and-done";
  const events = computeSaleEventDates(
    presetKey, offer.saleStartDate, offer.saleEndDate,
    sequence?.defaultSendTimeLocal || "09:00"
  );

  const renderedMessages = {};
  for (const ev of events) {
    renderedMessages[ev.phase] = renderSaleTemplate(ev.phase, templateVars);
  }

  // Compose promo image
  let composedImageUrl = null;
  const imageUrl = media?.imageUrl || media?.napaUrl ? null : null; // base image
  const baseImg = media?.imageUrl || null;
  if (baseImg && baseImg.includes("res.cloudinary.com")) {
    const dateLine = `${saleStartDisplay}\u2013${saleEndDisplay}`;
    composedImageUrl = buildPromoImageUrl(baseImg, {
      headline: offer.productName,
      price: salePriceFmt.formatted,
      ctaText: resolvedCta.imageBadgeText,
      dateLine,
    });
  } else if (baseImg) {
    composedImageUrl = baseImg;
  }

  // Timeline
  const timeline = events.map((ev, i) => ({
    index: i,
    phase: ev.phase,
    label: ev.label,
    date: ev.sendAtIso,
    isPast: ev.isPast,
  }));

  return jsonOk(corsHeaders, {
    renderedMessages,
    composedImageUrl,
    timeline,
    resolvedCta: { ctaText: resolvedCta.ctaText, destinationUrl: shortCtaUrl, imageBadgeText: resolvedCta.imageBadgeText },
    salePriceLine,
    salePriceFormatted: salePriceFmt.formatted,
    regularPriceFormatted: regularPriceFmt.formatted,
    warnings,
  });
}

async function handlePromoSchedule(request, env, corsHeaders) {
  const body = await request.json();
  const { campaignName, storeFilter, priorityOnly, emailFallback, offer, media, cta, sequence } = body;

  // Validation
  if (!campaignName || !campaignName.trim()) return jsonError(corsHeaders, "Campaign name is required.", 400);
  if (!offer || !offer.productName) return jsonError(corsHeaders, "Product name is required.", 400);
  if (!offer.salePrice) return jsonError(corsHeaders, "Sale price is required.", 400);
  if (!offer.saleStartDate || !offer.saleEndDate) return jsonError(corsHeaders, "Sale start and end dates are required.", 400);
  if (new Date(offer.saleEndDate) < new Date(offer.saleStartDate)) return jsonError(corsHeaders, "Sale end date must be on or after the start date.", 400);
  if (storeFilter && !VALID_STORES.includes(storeFilter)) return jsonError(corsHeaders, "Invalid store filter.", 400);

  const salePriceFmt = formatPromoPrice(offer.salePrice);
  if (!salePriceFmt.formatted) return jsonError(corsHeaders, "Enter a valid sale price.", 400);

  const presetKey = sequence?.preset || "one-and-done";
  if (!SALE_SEQUENCE_PRESETS[presetKey]) return jsonError(corsHeaders, "Invalid sequence preset.", 400);

  const salePriceLine = buildSalePriceLine(offer.regularPrice, offer.salePrice);
  const resolvedCta = resolvePromoCta({
    ctaType: cta?.type || "all_locations",
    storeFilter: storeFilter || null,
    napaUrl: media?.napaUrl || null,
    textOverride: cta?.textOverride || null,
    destinationOverride: cta?.destinationOverride || null,
  });

  // Shorten the CTA URL
  let shortCtaUrl = resolvedCta.destinationUrl;
  if (shortCtaUrl && shortCtaUrl.startsWith("http")) {
    shortCtaUrl = await shortenUrlsInText(shortCtaUrl, env);
  }

  const storeLabel = storeFilter ? (STORE_DISPLAY[storeFilter] || storeFilter) : "G&KK NAPA";
  const saleStartDisplay = new Date(offer.saleStartDate).toLocaleDateString("en-US", { month: "short", day: "numeric" });
  const saleEndDisplay = new Date(offer.saleEndDate).toLocaleDateString("en-US", { month: "short", day: "numeric" });

  const templateVars = {
    productName: offer.productName,
    salePriceLine,
    storeLabel,
    ctaText: resolvedCta.ctaText,
    ctaUrl: shortCtaUrl,
    saleStartDisplay,
    saleEndDisplay,
  };

  // Build composed image URL
  let mediaUrl = media?.imageUrl || null;
  if (mediaUrl && mediaUrl.includes("res.cloudinary.com")) {
    const dateLine = `${saleStartDisplay}\u2013${saleEndDisplay}`;
    mediaUrl = buildPromoImageUrl(mediaUrl, {
      headline: offer.productName,
      price: salePriceFmt.formatted,
      ctaText: resolvedCta.imageBadgeText,
      dateLine,
    });
  }

  const now = new Date().toISOString();

  // Store all promo metadata
  const promoMeta = {
    offer, media, cta: { type: cta?.type, textOverride: cta?.textOverride, destinationOverride: cta?.destinationOverride },
    resolvedCta, salePriceLine,
    priority_only: !!priorityOnly, email_fallback: !!emailFallback,
  };

  // Create campaign
  const firstBody = renderSaleTemplate("starts_today", templateVars);
  const campaignResult = await env.DB.prepare(
    "INSERT INTO campaigns (name, body, store_filter, recipient_count, promo_type, promo_meta, media_url, sequence_preset, created_at) VALUES (?, ?, ?, 0, 'promo', ?, ?, ?, ?)"
  ).bind(campaignName.trim(), firstBody, storeFilter || null, JSON.stringify(promoMeta), mediaUrl, presetKey, now).run();

  const campaignId = campaignResult.meta.last_row_id;

  // Generate events
  const events = computeSaleEventDates(
    presetKey, offer.saleStartDate, offer.saleEndDate,
    sequence?.defaultSendTimeLocal || "09:00"
  );
  const enabledPhases = sequence?.enabledPhases || null;
  await generateSaleSequenceEvents(env.DB, campaignId, events, templateVars, mediaUrl, enabledPhases);

  // Optionally send first touch immediately
  const sendFirstNow = sequence?.sendFirstTouchNow === true;
  let sentCount = 0;
  let failedCount = 0;
  let emailSent = 0;

  if (sendFirstNow) {
    // Find the first enabled, non-past event
    const firstEvent = await env.DB.prepare(
      "SELECT * FROM campaign_events WHERE campaign_id = ? AND status = 'scheduled' ORDER BY send_at ASC LIMIT 1"
    ).bind(campaignId).first();

    if (firstEvent) {
      let customerSql = "SELECT * FROM customers WHERE sms_status = 'subscribed'";
      const binds = [];
      if (storeFilter) { customerSql += " AND store = ?"; binds.push(storeFilter); }
      if (priorityOnly) { customerSql += " AND is_priority = 1"; }

      const stmt = env.DB.prepare(customerSql);
      const customers = binds.length > 0 ? await stmt.bind(...binds).all() : await stmt.all();

      let finalBody = await shortenUrlsInText(firstEvent.body, env);

      for (const customer of customers.results) {
        const result = await sendSms(env, customer.phone, finalBody, mediaUrl);
        await env.DB.prepare(
          "INSERT INTO messages (twilio_sid, customer_id, campaign_id, direction, body, status, error_code, created_at, updated_at) VALUES (?, ?, ?, 'outbound', ?, ?, ?, ?, ?)"
        ).bind(
          result.ok ? result.sid : null, customer.id, campaignId,
          finalBody, result.ok ? (result.status || "queued") : "failed",
          result.ok ? null : (result.error || "send_failed"), now, now
        ).run();
        if (result.ok) sentCount++;
        else failedCount++;
      }

      // Email fallback
      if (emailFallback && env.RESEND_API_KEY) {
        let emailSql = "SELECT * FROM customers WHERE sms_status != 'subscribed' AND email IS NOT NULL AND email != ''";
        const emailBinds = [];
        if (storeFilter) { emailSql += " AND store = ?"; emailBinds.push(storeFilter); }
        if (priorityOnly) { emailSql += " AND is_priority = 1"; }
        const emailStmt = env.DB.prepare(emailSql);
        const emailCustomers = emailBinds.length > 0 ? await emailStmt.bind(...emailBinds).all() : await emailStmt.all();

        for (const customer of emailCustomers.results) {
          const greeting = customer.name ? customer.name.split(' ')[0] : "Valued Customer";
          const canSms = customer.phone && customer.line_type && customer.line_type !== 'landline';
          const displayPhone = canSms ? customer.phone.replace(/^\+1(\d{3})(\d{3})(\d{4})$/, '($1) $2-$3') : null;
          let subscribeUrl = canSms
            ? `https://gkk-napa.com/s/${customer.short_code || await ensureShortCode(env.DB, customer.id)}`
            : 'https://gkk-napa.com/sms/subscribe';
          const emailMedia = mediaUrl && !mediaUrl.match(/\.(mp4|mov|webm|mpeg|3gp)(\?|$)/i) ? mediaUrl : null;
          const html = buildCampaignEmail(greeting, firstEvent.body, subscribeUrl, displayPhone, emailMedia);
          try {
            const resp = await fetch("https://api.resend.com/emails", {
              method: "POST",
              headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
              body: JSON.stringify({
                from: env.FROM_EMAIL, to: [customer.email],
                reply_to: env.REPLY_TO || "brian@danvillenapa.comcastbiz.net",
                subject: `${campaignName.trim()} \u2014 G&KK NAPA`, html,
              }),
            });
            if (resp.ok) emailSent++;
          } catch (e) {
            console.error(JSON.stringify({ tag: "PROMO_EMAIL_ERROR", customer_id: customer.id, error: e.message }));
          }
          await new Promise(r => setTimeout(r, 600));
        }
      }

      await env.DB.prepare(
        "UPDATE campaign_events SET status = 'sent', sent_count = ?, failed_count = ? WHERE id = ?"
      ).bind(sentCount, failedCount, firstEvent.id).run();

      await env.DB.prepare(
        "UPDATE campaigns SET recipient_count = ?, sent_count = ?, failed_count = ?, email_count = ? WHERE id = ?"
      ).bind(sentCount + failedCount, sentCount, failedCount, emailSent, campaignId).run();
    }
  }

  // Get event summary
  const allEvents = await env.DB.prepare(
    "SELECT id, event_index, label, status, send_at FROM campaign_events WHERE campaign_id = ? ORDER BY event_index ASC"
  ).bind(campaignId).all();

  const skippedCount = allEvents.results.filter(e => e.status === "skipped").length;
  const scheduledCount = allEvents.results.filter(e => e.status === "scheduled").length;

  return jsonOk(corsHeaders, {
    campaign_id: campaignId,
    events: allEvents.results,
    scheduled_count: scheduledCount,
    skipped_count: skippedCount,
    immediate_send: sendFirstNow,
    sent: sentCount,
    failed: failedCount,
    email_sent: emailSent,
  });
}

async function handlePromoCancel(path, env, corsHeaders) {
  const campaignId = parseInt(path.split("/").pop());
  const result = await env.DB.prepare(
    "UPDATE campaign_events SET status = 'cancelled' WHERE campaign_id = ? AND status = 'scheduled'"
  ).bind(campaignId).run();

  return jsonOk(corsHeaders, { cancelled: result.meta.changes });
}

async function handlePromoEvents(url, env, corsHeaders) {
  const campaignId = url.searchParams.get("campaign_id");
  if (!campaignId) return jsonError(corsHeaders, "campaign_id is required.", 400);

  const events = await env.DB.prepare(
    "SELECT * FROM campaign_events WHERE campaign_id = ? ORDER BY event_index ASC"
  ).bind(parseInt(campaignId)).all();

  return jsonOk(corsHeaders, events.results);
}

// In-memory cache for NAPA part lookups (survives within a single worker instance)
const napaPartCache = new Map();
const NAPA_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

async function handleNapaPartSearch(request, env, corsHeaders) {
  const body = await request.json();
  const { partNumber } = body;
  if (!partNumber || !partNumber.trim()) return jsonError(corsHeaders, "Part number is required.", 400);

  const clean = partNumber.trim().replace(/\s+/g, "");

  // Check in-memory cache first
  const cached = napaPartCache.get(clean);
  if (cached && (Date.now() - cached.ts) < NAPA_CACHE_TTL) {
    return jsonOk(corsHeaders, cached.data);
  }

  try {
    // Try direct product page first: /en/p/PARTNUMBER (reuse HTML to avoid double-fetch)
    const directUrl = `https://www.napaonline.com/en/p/${encodeURIComponent(clean)}`;
    const directHtml = await fetchNapaHtml(directUrl);
    let meta = null;
    if (directHtml) {
      meta = parseNapaMeta(directHtml);
      if (!meta.image || !meta.title) meta = null; // not a real product page
    }

    // Fallback or supplement from search page
    const searchUrl = `https://www.napaonline.com/en/search?text=${encodeURIComponent(clean)}`;
    if (!meta) {
      const searchHtml = await fetchNapaHtml(searchUrl);
      if (!searchHtml) throw new Error("Search failed");
      const linkMatch = searchHtml.match(/href="(\/en\/p\/[^"]+)"/i);
      if (!linkMatch) return jsonError(corsHeaders, "No results found for part number.", 404);
      const productUrl = `https://www.napaonline.com${linkMatch[1]}`;
      meta = await fetchNapaMeta(productUrl);
      if (!meta.image) return jsonError(corsHeaders, "Product found but no image available.", 404);
    }

    // If product page didn't have price, try search results page (prices often rendered in listing)
    if (!meta.price) {
      const searchHtml = await fetchNapaHtml(searchUrl);
      if (searchHtml) {
        const searchMeta = parseNapaMeta(searchHtml);
        if (searchMeta.price) meta.price = searchMeta.price;
      }
    }

    // Cache the result
    napaPartCache.set(clean, { data: meta, ts: Date.now() });

    return jsonOk(corsHeaders, meta);
  } catch (e) {
    return jsonError(corsHeaders, e.message, 400);
  }
}

async function handleNapaLookup(request, env, corsHeaders) {
  const body = await request.json();
  const { url: napaUrl } = body;

  if (!napaUrl) return jsonError(corsHeaders, "URL is required.", 400);

  try {
    const meta = await fetchNapaMeta(napaUrl);
    return jsonOk(corsHeaders, meta);
  } catch (e) {
    return jsonError(corsHeaders, e.message, 400);
  }
}

async function handleListPromoAssets(env, corsHeaders) {
  const assets = await env.DB.prepare("SELECT * FROM promo_assets ORDER BY created_at DESC").all();
  return jsonOk(corsHeaders, assets.results);
}

async function handleCreatePromoAsset(request, env, corsHeaders) {
  const body = await request.json();
  const { name, cloudinary_url, thumb_url, asset_type } = body;

  if (!name || !cloudinary_url) return jsonError(corsHeaders, "Name and cloudinary_url are required.", 400);

  const now = new Date().toISOString();
  const result = await env.DB.prepare(
    "INSERT INTO promo_assets (name, cloudinary_url, thumb_url, asset_type, created_at) VALUES (?, ?, ?, ?, ?)"
  ).bind(name, cloudinary_url, thumb_url || null, asset_type || "image", now).run();

  return jsonOk(corsHeaders, { id: result.meta.last_row_id, success: true }, 201);
}

// ═══════════════════════════════════════════════════════════════
// Admin: Campaign History
// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════
// Media Library
// ═══════════════════════════════════════════════════════════════

async function handleMediaLibrary(env, corsHeaders) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS media_library (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      url TEXT NOT NULL UNIQUE,
      label TEXT,
      created_at TEXT NOT NULL
    )
  `).run();

  const items = await env.DB.prepare(
    "SELECT id, url, label, created_at FROM media_library ORDER BY created_at DESC"
  ).all();
  return jsonOk(corsHeaders, items.results);
}

async function handleSaveToLibrary(request, env, corsHeaders) {
  const { url, label } = await request.json();
  if (!url) return jsonError(corsHeaders, "URL is required.", 400);

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS media_library (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      url TEXT NOT NULL UNIQUE,
      label TEXT,
      created_at TEXT NOT NULL
    )
  `).run();

  const now = new Date().toISOString();
  try {
    await env.DB.prepare(
      "INSERT INTO media_library (url, label, created_at) VALUES (?, ?, ?)"
    ).bind(url, label || null, now).run();
  } catch (e) {
    // UNIQUE constraint — already in library, just update label
    if (label) {
      await env.DB.prepare("UPDATE media_library SET label = ? WHERE url = ?").bind(label, url).run();
    }
  }
  return jsonOk(corsHeaders, { ok: true });
}

async function handleListCampaigns(env, corsHeaders) {
  const campaigns = await env.DB.prepare(
    "SELECT * FROM campaigns ORDER BY created_at DESC"
  ).all();

  // For promo campaigns, attach event summary
  const results = [];
  for (const c of campaigns.results) {
    if (c.promo_type === "promo") {
      const events = await env.DB.prepare(
        "SELECT id, event_index, label, status, sent_count, failed_count, send_at FROM campaign_events WHERE campaign_id = ? ORDER BY event_index ASC"
      ).bind(c.id).all();
      results.push({ ...c, events: events.results });
    } else {
      results.push({ ...c, events: [] });
    }
  }

  return jsonOk(corsHeaders, results);
}

async function handleGetCampaign(path, env, corsHeaders) {
  const id = parseInt(path.split("/").pop());
  const campaign = await env.DB.prepare("SELECT * FROM campaigns WHERE id = ?").bind(id).first();
  if (!campaign) return jsonError(corsHeaders, "Campaign not found.", 404);

  const messages = await env.DB.prepare(
    "SELECT m.*, c.name as customer_name, c.phone as customer_phone FROM messages m JOIN customers c ON m.customer_id = c.id WHERE m.campaign_id = ? ORDER BY m.created_at ASC"
  ).bind(id).all();

  return jsonOk(corsHeaders, { ...campaign, messages: messages.results });
}

// ═══════════════════════════════════════════════════════════════
// Creative Studio
// ═══════════════════════════════════════════════════════════════

async function handleRemoveBg(request, env, corsHeaders) {
  const { imageUrl } = await request.json();
  if (!imageUrl) return jsonError(corsHeaders, "Missing imageUrl", 400);

  // Validate hostname — only allow NAPA CDN domains
  try {
    const parsed = new URL(imageUrl);
    const allowed = ["www.napaonline.com", "napaonline.com", "media.napaonline.com", "images.napaonline.com"];
    if (!allowed.some(h => parsed.hostname === h || parsed.hostname.endsWith("." + h))) {
      return jsonError(corsHeaders, "Host not allowed", 403);
    }
  } catch {
    return jsonError(corsHeaders, "Invalid URL", 400);
  }

  try {
    // Upgrade to high-res preset for better bg removal quality
    let fetchUrl = imageUrl;
    if (fetchUrl.includes("media.napaonline.com/is/image/") && !fetchUrl.includes("preset=")) {
      fetchUrl += (fetchUrl.includes("?") ? "&" : "?") + "preset=webproofxlarge";
    }

    // Fetch image ourselves — NAPA blocks Replicate's servers (403)
    const imgResp = await fetch(fetchUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; GKK-NAPA-Bot/1.0)" },
    });
    if (!imgResp.ok) {
      return jsonError(corsHeaders, `Image fetch failed: HTTP ${imgResp.status}`, 502);
    }
    const imgBuf = await imgResp.arrayBuffer();
    const bytes = new Uint8Array(imgBuf);
    // Chunk-based base64 to avoid O(n²) string concat and CPU limit
    const chunks = [];
    for (let i = 0; i < bytes.length; i += 8192) {
      chunks.push(String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 8192, bytes.length))));
    }
    const b64 = btoa(chunks.join(""));
    const contentType = (imgResp.headers.get("content-type") || "image/jpeg").split(";")[0].trim();
    const dataUri = `data:${contentType};base64,${b64}`;

    const resp = await fetch("https://api.replicate.com/v1/predictions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.REPLICATE_API_TOKEN}`,
        "Content-Type": "application/json",
        "Prefer": "wait=20",
      },
      body: JSON.stringify({
        version: "f74986db0355b58403ed20963af156525e2891ea3c2d499bfbfb2a28cd87c5d7",
        input: { image: dataUri },
      }),
    });
    const data = await resp.json();
    if (!resp.ok || data.status === "failed" || !data.output) {
      return jsonError(corsHeaders, `Replicate failed: ${data.error || data.status || JSON.stringify(data)}`, 502);
    }
    return new Response(JSON.stringify({ url: data.output }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    return jsonError(corsHeaders, `Remove-bg error: ${err.message}`, 500);
  }
}

async function handleProxyImage(request, corsHeaders) {
  const url = new URL(request.url);
  const imageUrl = url.searchParams.get("url");
  if (!imageUrl) return jsonError(corsHeaders, "Missing url parameter.", 400);

  try {
    const parsed = new URL(imageUrl);
    const allowed = [
      "www.napaonline.com", "napaonline.com",
      "media.napaonline.com", "images.napaonline.com",
      "res.cloudinary.com", "cloudinary.com",
      "replicate.delivery",
    ];
    if (!allowed.some(h => parsed.hostname === h || parsed.hostname.endsWith("." + h))) {
      return jsonError(corsHeaders, "Host not allowed.", 403);
    }
  } catch {
    return jsonError(corsHeaders, "Invalid URL.", 400);
  }

  const resp = await fetch(imageUrl, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; GKK-NAPA-Bot/1.0)" },
  });
  if (!resp.ok) return new Response("Upstream error", { status: resp.status });

  let contentType = resp.headers.get("content-type") || "image/png";
  contentType = contentType.split(";")[0].trim();

  return new Response(resp.body, {
    headers: {
      ...corsHeaders,
      "Content-Type": contentType,
      "Cache-Control": "public, max-age=86400",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

async function ensureCreativesTable(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS promo_creatives (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      template_id TEXT NOT NULL DEFAULT 'promo_split_v1',
      status TEXT NOT NULL DEFAULT 'draft',
      image_content_json TEXT NOT NULL,
      sms_content_json TEXT NOT NULL,
      cta_json TEXT NOT NULL,
      media_json TEXT NOT NULL,
      render_json TEXT,
      version INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run();
}

async function handleCreativePreview(request, env, corsHeaders) {
  const body = await request.json();
  const { imageContent, smsContent, cta, media, storeContext } = body;

  if (!imageContent) return jsonError(corsHeaders, "imageContent is required.", 400);
  if (!imageContent.salePrice) return jsonError(corsHeaders, "Sale price is required.", 400);
  if (!imageContent.productName) return jsonError(corsHeaders, "Product name is required.", 400);

  // Price formatting
  const salePriceFmt = formatPromoPrice(imageContent.salePrice);
  const regularPriceFmt = imageContent.regularPrice ? formatPromoPrice(imageContent.regularPrice) : { formatted: null, warning: null };
  const warnings = [];
  if (salePriceFmt.warning) warnings.push(salePriceFmt.warning);
  if (regularPriceFmt.warning) warnings.push(regularPriceFmt.warning);
  if (!salePriceFmt.formatted) return jsonError(corsHeaders, "Enter a valid sale price.", 400);

  const salePriceLine = buildSalePriceLine(imageContent.regularPrice, imageContent.salePrice);

  // CTA resolution
  const resolvedCta = resolvePromoCta({
    ctaType: cta?.type || "all_locations",
    storeFilter: storeContext || null,
    napaUrl: media?.napaUrl || null,
    textOverride: null,
    destinationOverride: cta?.destinationOverride || null,
  });

  // Shorten CTA URL
  let shortCtaUrl = resolvedCta.destinationUrl;
  if (shortCtaUrl && shortCtaUrl.startsWith("http") && !shortCtaUrl.includes("gkk-napa.com/l/")) {
    shortCtaUrl = await shortenUrlsInText(shortCtaUrl, env);
  }

  // Build SMS preview from body template
  let smsPreview = (smsContent?.body || "").trim();
  if (smsPreview) {
    smsPreview = smsPreview
      .replace(/\{\{sale_price_line\}\}/g, salePriceLine)
      .replace(/\{\{product_name\}\}/g, imageContent.productName || "")
      .replace(/\{\{sale_price\}\}/g, salePriceFmt.formatted || "")
      .replace(/\{\{regular_price\}\}/g, regularPriceFmt.formatted || "")
      .replace(/\{\{cta_text\}\}/g, resolvedCta.ctaText || "")
      .replace(/\{\{cta_url\}\}/g, shortCtaUrl || "");
    smsPreview = await shortenUrlsInText(smsPreview, env);
    smsPreview += "\n\nReply STOP to opt out.";
  }

  return jsonOk(corsHeaders, {
    smsPreview,
    resolvedCta: { ctaText: resolvedCta.ctaText, destinationUrl: shortCtaUrl, badgeText: resolvedCta.imageBadgeText },
    salePriceLine,
    salePriceFormatted: salePriceFmt.formatted,
    regularPriceFormatted: regularPriceFmt.formatted,
    warnings,
  });
}

async function handleCreativeSave(request, env, corsHeaders) {
  const body = await request.json();
  const { name, imageContent, smsContent, cta, media, composedImageUrl } = body;

  if (!imageContent) return jsonError(corsHeaders, "imageContent is required.", 400);
  if (!imageContent.salePrice) return jsonError(corsHeaders, "Sale price is required.", 400);

  await ensureCreativesTable(env.DB);

  const now = new Date().toISOString();
  const result = await env.DB.prepare(
    "INSERT INTO promo_creatives (name, image_content_json, sms_content_json, cta_json, media_json, render_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(
    name || "Untitled",
    JSON.stringify(imageContent),
    JSON.stringify(smsContent || {}),
    JSON.stringify(cta || {}),
    JSON.stringify(media || {}),
    JSON.stringify({ composedImageUrl: composedImageUrl || null }),
    now, now
  ).run();

  return jsonOk(corsHeaders, { id: result.meta.last_row_id, success: true }, 201);
}

async function handleGetCreative(path, env, corsHeaders) {
  await ensureCreativesTable(env.DB);
  const id = parseInt(path.split("/").pop());
  const row = await env.DB.prepare("SELECT * FROM promo_creatives WHERE id = ?").bind(id).first();
  if (!row) return jsonError(corsHeaders, "Creative not found.", 404);

  return jsonOk(corsHeaders, {
    ...row,
    imageContent: JSON.parse(row.image_content_json),
    smsContent: JSON.parse(row.sms_content_json),
    cta: JSON.parse(row.cta_json),
    media: JSON.parse(row.media_json),
    render: row.render_json ? JSON.parse(row.render_json) : null,
  });
}

async function handleListCreatives(env, corsHeaders) {
  await ensureCreativesTable(env.DB);
  const rows = await env.DB.prepare(
    "SELECT id, name, status, template_id, updated_at, created_at FROM promo_creatives ORDER BY updated_at DESC"
  ).all();
  return jsonOk(corsHeaders, rows.results);
}
