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
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function jsonError(corsHeaders, message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
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

// ─── Twilio helpers ──────────────────────────────────────────
async function sendSms(env, to, body) {
  const url = `https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_ACCOUNT_SID}/Messages.json`;
  const params = new URLSearchParams({
    From: env.TWILIO_PHONE_NUMBER,
    To: to,
    Body: body,
    StatusCallback: `https://gkk-napa-sms.kellyraeknight78.workers.dev/twilio/status`,
  });

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

// ─── Main fetch handler ──────────────────────────────────────
export default {
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

      // ── Admin: DELETE /admin/customers/:id ──
      if (request.method === "DELETE" && path.match(/^\/admin\/customers\/\d+$/)) {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleDeleteCustomer(path, env, corsHeaders);
      }

      // ── Admin: POST /admin/import ──
      if (request.method === "POST" && path === "/admin/import") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleImport(request, env, corsHeaders);
      }

      // ── Admin: POST /admin/invite ──
      if (request.method === "POST" && path === "/admin/invite") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleInvite(request, env, corsHeaders);
      }

      // ── Admin: POST /admin/send ──
      if (request.method === "POST" && path === "/admin/send") {
        if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
        return handleSendCampaign(request, env, corsHeaders);
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
  const { phone: rawPhone, store } = body;

  if (!rawPhone) return jsonError(corsHeaders, "Phone number is required.", 400);

  const phone = normalizePhone(rawPhone);
  if (!phone) return jsonError(corsHeaders, "Invalid phone number. Please enter a 10-digit US number.", 400);

  if (store && !VALID_STORES.includes(store)) {
    return jsonError(corsHeaders, "Invalid store.", 400);
  }

  const now = new Date().toISOString();

  // Check if customer already exists
  const existing = await env.DB.prepare("SELECT id, sms_status FROM customers WHERE phone = ?").bind(phone).first();

  if (!existing) {
    return jsonError(corsHeaders, "This number isn't in our system. Please contact your local G&KK NAPA store to sign up.", 404);
  }

  if (existing.sms_status === "subscribed") {
    return jsonOk(corsHeaders, { success: true, message: "You're already subscribed!" });
  }

  await env.DB.prepare(
    "UPDATE customers SET sms_status = 'subscribed', sms_consent_at = ?, updated_at = ? WHERE id = ?"
  ).bind(now, now, existing.id).run();

  // Send confirmation SMS
  if (env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN) {
    const confirmMsg =
      "Welcome to G&KK NAPA text updates! You'll receive order notifications, store hours, and occasional deals. Reply STOP to opt out, HELP for help. Msg&data rates may apply.";
    const result = await sendSms(env, phone, confirmMsg);

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

  let sql = "SELECT * FROM customers WHERE 1=1";
  const binds = [];

  if (store && VALID_STORES.includes(store)) {
    sql += " AND store = ?";
    binds.push(store);
  }
  if (status && ["none", "invited", "subscribed", "stopped"].includes(status)) {
    sql += " AND sms_status = ?";
    binds.push(status);
  }
  if (q) {
    sql += " AND (name LIKE ? OR phone LIKE ? OR email LIKE ?)";
    const search = `%${q}%`;
    binds.push(search, search, search);
  }

  sql += " ORDER BY name ASC, created_at DESC";

  const stmt = env.DB.prepare(sql);
  const result = binds.length > 0 ? await stmt.bind(...binds).all() : await stmt.all();

  return jsonOk(corsHeaders, result.results);
}

async function handleAddCustomer(request, env, corsHeaders) {
  const body = await request.json();
  const { name, phone: rawPhone, email, store, notes } = body;

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

  const now = new Date().toISOString();
  const result = await env.DB.prepare(
    "INSERT INTO customers (phone, name, email, store, source, notes, created_at, updated_at) VALUES (?, ?, ?, ?, 'admin', ?, ?, ?)"
  ).bind(phone, name || null, email || null, store || null, notes || null, now, now).run();

  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(result.meta.last_row_id).first();
  return jsonOk(corsHeaders, customer, 201);
}

async function handleUpdateCustomer(request, path, env, corsHeaders) {
  const id = parseInt(path.split("/").pop());
  const body = await request.json();
  const { name, email, store, notes, sms_status } = body;

  const existing = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(id).first();
  if (!existing) return jsonError(corsHeaders, "Customer not found.", 404);

  if (store && !VALID_STORES.includes(store)) {
    return jsonError(corsHeaders, "Invalid store.", 400);
  }
  if (sms_status && !["none", "invited", "subscribed", "stopped"].includes(sms_status)) {
    return jsonError(corsHeaders, "Invalid status.", 400);
  }

  const now = new Date().toISOString();
  const updates = [];
  const binds = [];

  if (name !== undefined) { updates.push("name = ?"); binds.push(name || null); }
  if (email !== undefined) { updates.push("email = ?"); binds.push(email || null); }
  if (store !== undefined) { updates.push("store = ?"); binds.push(store || null); }
  if (notes !== undefined) { updates.push("notes = ?"); binds.push(notes || null); }
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

  await env.DB.prepare("DELETE FROM customers WHERE id = ?").bind(id).run();
  return jsonOk(corsHeaders, { success: true });
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
    const firstName = customer.name ? customer.name.split(" ")[0] : "Valued Customer";

    const html = buildInviteEmail(firstName, storeName, emailIntro, emailBullets);

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
          reply_to: "napa.danville@comcastbiz.net",
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
  }

  return jsonOk(corsHeaders, { sent, failed, total_eligible: customers.results.length });
}

function buildInviteEmail(firstName, storeName, customIntro, customBullets) {
  const intro = customIntro || `We're excited to offer text updates from ${storeName}! Subscribe to get:`;
  const bullets = customBullets || ["Order-ready notifications", "Store hours & closure alerts", "Occasional deals & promotions"];
  const bulletRows = bullets.map(b => `  <tr><td style="padding:6px 0;font-size:15px;color:#333;">&#10003;&nbsp;&nbsp;${escHtml(b)}</td></tr>`).join("\n");

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f3f4f6;font-family:Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f3f4f6;">
<tr><td align="center" style="padding:24px 16px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);">

<!-- NAPA Header -->
<tr><td style="background-color:#2b2f84;padding:20px 24px;text-align:center;">
<img src="https://gkk-napa.com/assets/napa-logo.png" alt="NAPA Auto Parts" height="40" style="display:inline-block;height:40px;width:auto;">
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

<!-- CTA Button -->
<tr><td align="center" style="padding:0 24px 32px;">
<a href="https://gkk-napa.com/sms/subscribe" target="_blank"
   style="display:inline-block;background-color:#FFC836;color:#0A0094;font-size:16px;font-weight:700;text-decoration:none;padding:14px 32px;border-radius:8px;text-transform:uppercase;letter-spacing:0.5px;">
  Subscribe Now
</a>
</td></tr>

<!-- Disclosure -->
<tr><td style="padding:0 24px 24px;">
<p style="margin:0;font-size:12px;color:#888;line-height:1.5;">
  Message frequency varies. Msg &amp; data rates may apply. Reply STOP to opt out, HELP for help.
  Consent is not a condition of purchase. Carriers are not liable for delayed or undelivered messages.
  <a href="https://gkk-napa.com/privacy.html" style="color:#2b2f84;">Privacy Policy</a> |
  <a href="https://gkk-napa.com/terms.html" style="color:#2b2f84;">Terms of Service</a>
</p>
</td></tr>

<!-- Footer -->
<tr><td style="background-color:#f9fafb;padding:16px 24px;border-top:1px solid #e5e7eb;">
<p style="margin:0;font-size:12px;color:#888;text-align:center;">G&amp;KK NAPA Auto Parts &middot; <a href="https://gkk-napa.com" style="color:#2b2f84;">gkk-napa.com</a></p>
</td></tr>

</table>
</td></tr>
</table>
</body></html>`;
}

// ═══════════════════════════════════════════════════════════════
// Phase 4: SMS Campaign Sending
// ═══════════════════════════════════════════════════════════════

async function handleSendCampaign(request, env, corsHeaders) {
  const body = await request.json();
  const { name, body: messageBody, store } = body;

  if (!name || !name.trim()) return jsonError(corsHeaders, "Campaign name is required.", 400);
  if (!messageBody || !messageBody.trim()) return jsonError(corsHeaders, "Message body is required.", 400);
  if (messageBody.length > 1500) return jsonError(corsHeaders, "Message body must be under 1500 characters.", 400);

  if (store && !VALID_STORES.includes(store)) {
    return jsonError(corsHeaders, "Invalid store filter.", 400);
  }

  // Append opt-out footer
  const fullMessage = messageBody.trim() + "\n\nReply STOP to opt out.";

  // Query subscribed customers
  let customerSql = "SELECT * FROM customers WHERE sms_status = 'subscribed'";
  const binds = [];
  if (store) {
    customerSql += " AND store = ?";
    binds.push(store);
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
    const result = await sendSms(env, customer.phone, fullMessage);

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

  // Update campaign counters
  await env.DB.prepare(
    "UPDATE campaigns SET sent_count = ?, failed_count = ? WHERE id = ?"
  ).bind(sentCount, failedCount, campaignId).run();

  return jsonOk(corsHeaders, {
    campaign_id: campaignId,
    recipient_count: customers.results.length,
    sent: sentCount,
    failed: failedCount,
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
// Admin: Campaign History
// ═══════════════════════════════════════════════════════════════

async function handleListCampaigns(env, corsHeaders) {
  const campaigns = await env.DB.prepare(
    "SELECT * FROM campaigns ORDER BY created_at DESC"
  ).all();
  return jsonOk(corsHeaders, campaigns.results);
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
