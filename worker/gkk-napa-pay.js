/**
 * G&KK NAPA Bill Pay - Cloudflare Worker
 *
 * Creates Stripe Checkout Sessions for ACH and Card payments.
 * Card payments include a convenience fee (gross-up calculation).
 *
 * Environment Variables Required:
 *   STRIPE_SECRET_KEY - Stripe secret key (test or live)
 *   STRIPE_WEBHOOK_SECRET - Webhook signing secret (whsec_...)
 *   SUCCESS_URL - Redirect URL after successful payment
 *   CANCEL_URL - Redirect URL if user cancels
 *   RESEND_API_KEY - Resend API key for email notifications
 *   FROM_EMAIL - Sender email address (e.g., notifications@gkk-napa.com)
 *   NOTIFY_EMAILS - Comma-separated recipient emails
 *
 * Deploy via Cloudflare Dashboard:
 *   Workers & Pages > Create Worker > Paste this code
 *   Settings > Variables > Add the env vars above
 */

// Convenience fee constants for card payments
const CARD_PCT = 0.029; // 2.9%
const CARD_FIXED_CENTS = 30; // $0.30

// Payment limits (keep in sync with frontend)
const MIN_CENTS = 100;           // $1.00
const ACH_MAX_CENTS = 5000000;   // $50,000.00
const CARD_MAX_CENTS = 1000000;  // $10,000.00

// Format unix timestamp to readable date (Central Time)
function formatDate(unixTimestamp) {
  if (!unixTimestamp) return 'N/A';
  const date = new Date(unixTimestamp * 1000);
  return date.toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    timeZone: 'America/Chicago'
  });
}

// Calculate business days between two unix timestamps (excludes weekends)
function businessDaysBetween(startUnix, endUnix) {
  if (!startUnix || !endUnix) return 0;
  const start = new Date(startUnix * 1000);
  const end = new Date(endUnix * 1000);
  let count = 0;
  const current = new Date(start);
  current.setDate(current.getDate() + 1);
  while (current <= end) {
    const day = current.getDay();
    if (day !== 0 && day !== 6) count++;
    current.setDate(current.getDate() + 1);
  }
  return Math.max(count, 1);
}

// Allowed origins for CORS
const allowedOrigins = new Set([
  "https://gkk-napa.com",
  "https://www.gkk-napa.com",
  "https://gkk-napa.pages.dev",
]);

// Check if origin is allowed (including preview subdomains)
function isAllowedOrigin(origin) {
  if (!origin) return false;
  if (allowedOrigins.has(origin)) return true;
  // Allow Cloudflare Pages preview deployments (e.g., https://<hash>.gkk-napa.pages.dev)
  if (origin.endsWith(".gkk-napa.pages.dev")) return true;
  return false;
}

// Get CORS headers based on request origin
function getCorsHeaders(request) {
  const origin = request.headers.get("Origin");
  return {
    "Access-Control-Allow-Origin": isAllowedOrigin(origin) ? origin : "https://gkk-napa.com",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

// ============ Stripe Webhook Signature Verification ============

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return res === 0;
}

function parseStripeSignatureHeader(sigHeader) {
  // Example: "t=1700000000,v1=abc...,v0=..."
  const parts = sigHeader.split(",").map(s => s.trim());
  const out = {};
  for (const p of parts) {
    const [k, v] = p.split("=");
    if (!k || !v) continue;
    (out[k] ||= []).push(v);
  }
  return out;
}

async function hmacSha256Hex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sigBuf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verifyStripeWebhookSignature(request, webhookSecret, toleranceSeconds = 300) {
  const sigHeader = request.headers.get("stripe-signature");
  if (!sigHeader) return { ok: false, error: "Missing stripe-signature header" };

  const rawBody = await request.text(); // MUST be raw
  const parsed = parseStripeSignatureHeader(sigHeader);

  const t = parsed.t?.[0];
  const v1s = parsed.v1 || [];
  if (!t || v1s.length === 0) return { ok: false, error: "Malformed stripe-signature header" };

  // Optional replay protection
  const now = Math.floor(Date.now() / 1000);
  const ts = Number(t);
  if (!Number.isFinite(ts) || Math.abs(now - ts) > toleranceSeconds) {
    return { ok: false, error: "Timestamp outside tolerance" };
  }

  const signedPayload = `${t}.${rawBody}`;
  const expected = await hmacSha256Hex(webhookSecret, signedPayload);

  const match = v1s.some(v1 => timingSafeEqual(v1, expected));
  if (!match) return { ok: false, error: "Invalid signature" };

  return { ok: true, rawBody };
}

export default {
  async fetch(request, env) {
    const corsHeaders = getCorsHeaders(request);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    // Only handle POST /create-checkout-session
    if (request.method === 'POST' && url.pathname === '/create-checkout-session') {
      return handleCreateCheckoutSession(request, env, corsHeaders);
    }

    // Stripe webhook endpoint (matches Stripe config: /stripe-webhook)
    if (url.pathname === "/stripe-webhook") {
      if (request.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405 });
      }

      if (!env.STRIPE_WEBHOOK_SECRET) {
        return new Response(JSON.stringify({ error: "Missing STRIPE_WEBHOOK_SECRET" }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }

      const verified = await verifyStripeWebhookSignature(request, env.STRIPE_WEBHOOK_SECRET);
      if (!verified.ok) {
        return new Response(JSON.stringify({ error: verified.error }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }

      let event;
      try {
        event = JSON.parse(verified.rawBody);
      } catch {
        return new Response(JSON.stringify({ error: "Invalid JSON payload" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }

      const type = event?.type;
      const obj = event?.data?.object || {};

      // Extract metadata fields
      const sessionId = obj.id;
      const company = obj.metadata?.company;
      const accountNumber = obj.metadata?.account_number;
      const statementNumber = obj.metadata?.statement_number;
      const store = obj.metadata?.store;
      const payMethod = obj.metadata?.pay_method;
      const paymentStatus = obj.payment_status;

      // Amount fields
      const paymentAmountCents = parseInt(obj.metadata?.payment_amount_cents || "0", 10);
      const discountChecked = obj.metadata?.discount_checked === "true";
      const convenienceFeeCents = parseInt(obj.metadata?.convenience_fee_cents || "0", 10);
      const totalChargedCents = parseInt(obj.metadata?.total_charged_cents || "0", 10);

      const payerEmail = obj.customer_details?.email || obj.metadata?.customer_email;
      const payerPhone = obj.metadata?.customer_phone || obj.customer_details?.phone;

      const isSuccess = (type === "checkout.session.completed" || type === "checkout.session.async_payment_succeeded");
      const isFailure = (type === "checkout.session.async_payment_failed" || type === "checkout.session.expired");

      console.log(JSON.stringify({
        tag: "STRIPE_WEBHOOK",
        type,
        isSuccess,
        isFailure,
        sessionId,
        company,
        accountNumber,
        statementNumber,
        store,
        payMethod,
        paymentStatus,
        paymentAmountCents,
        discountChecked,
        convenienceFeeCents,
        totalChargedCents,
        currency: obj.currency,
        payerEmail,
        payerPhone,
        created: event?.created
      }));

      // Send email notifications for key events
      const shouldNotify = (
        type === "checkout.session.completed" ||
        type === "checkout.session.async_payment_succeeded" ||
        type === "checkout.session.async_payment_failed"
      );

      if (shouldNotify && env.RESEND_API_KEY && env.FROM_EMAIL && env.NOTIFY_EMAILS) {
        try {
          const paymentAmountUsd = (paymentAmountCents / 100).toFixed(2);
          const convenienceFeeUsd = (convenienceFeeCents / 100).toFixed(2);
          const totalChargedUsd = (totalChargedCents / 100).toFixed(2);

          // Estimate Stripe fees (2.9% + $0.30 for card, 0.8% capped at $5 for ACH)
          let estimatedStripeFee = "N/A";
          let estimatedNetDeposit = "N/A";
          if (totalChargedCents > 0) {
            let stripeFeeAmount;
            if (payMethod === "card") {
              stripeFeeAmount = Math.round(totalChargedCents * 0.029 + 30);
            } else if (payMethod === "ach") {
              stripeFeeAmount = Math.min(Math.round(totalChargedCents * 0.008), 500);
            }
            if (stripeFeeAmount) {
              estimatedStripeFee = `$${(stripeFeeAmount / 100).toFixed(2)}`;
              estimatedNetDeposit = `$${((totalChargedCents - stripeFeeAmount) / 100).toFixed(2)}`;
            }
          }

          // Extract dates
          const paymentDate = formatDate(obj.created);
          const eventDate = formatDate(event.created);

          // Build email subject and body
          let subject, statusText, statusColor, statusBg, dateRows, statusSubtext = '';

          if (type === "checkout.session.completed") {
            const emoji = payMethod === "card" ? "\u{1F4B0}\u{1F4B3}" : "\u{1F4B0}\u{1F3E6}";
            statusText = "Payment Received";
            statusColor = "#16a34a"; // green
            statusBg = "#f0fdf4";
            subject = `${emoji} Payment Received - ${store} - $${paymentAmountUsd}`;
            dateRows = `<tr><td style="padding:6px 12px;color:#555;font-size:14px;">Payment Date</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">${eventDate}</td></tr>`;
          } else if (type === "checkout.session.async_payment_succeeded") {
            const clearDays = businessDaysBetween(obj.created, event.created);
            statusText = "ACH Cleared";
            statusSubtext = `in ${clearDays} business day${clearDays !== 1 ? 's' : ''}`;
            statusColor = "#2563eb"; // blue
            statusBg = "#eff6ff";
            subject = `\u2705\u{1F3E6} ACH Cleared (${clearDays}d) - ${store} - $${paymentAmountUsd}`;
            dateRows = `<tr><td style="padding:6px 12px;color:#555;font-size:14px;">Payment Date</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">${paymentDate}</td></tr><tr><td style="padding:6px 12px;color:#555;font-size:14px;">Date Cleared</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">${eventDate}</td></tr>`;
          } else if (type === "checkout.session.async_payment_failed") {
            statusText = "ACH FAILED";
            statusColor = "#dc2626"; // red
            statusBg = "#fef2f2";
            subject = `\u274C\u{1F3E6} ACH FAILED - ${store} - ACCT# ${accountNumber || 'N/A'} - DO NOT CREDIT`;
            dateRows = `<tr><td style="padding:6px 12px;color:#555;font-size:14px;">Payment Date</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">${paymentDate}</td></tr><tr><td style="padding:6px 12px;color:#555;font-size:14px;">Date Failed</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">${eventDate}</td></tr>`;
          }

          // Stripe dashboard link
          const paymentIntentId = obj.payment_intent;
          const stripeLink = paymentIntentId
            ? `https://dashboard.stripe.com/payments/${paymentIntentId}`
            : `https://dashboard.stripe.com/checkout/sessions/${sessionId}`;

          const methodLabel = payMethod === "ach" ? "Bank (ACH)" : payMethod === "card" ? "Credit Card" : payMethod || "N/A";

          // Build payment breakdown rows (different for ACH vs Card vs Failed)
          let breakdownRows = '';

          if (type === "checkout.session.async_payment_failed") {
            // Failed ACH — Stripe does NOT charge fees on failed async payments
            breakdownRows += `<tr><td style="padding:6px 12px;color:#555;font-size:14px;">Payment Amount</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">$${paymentAmountUsd}</td></tr>`;
            if (discountChecked) {
              breakdownRows += `<tr><td style="padding:6px 12px;color:#555;font-size:14px;">Discount on Invoice</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">Yes</td></tr>`;
            }
            breakdownRows += `<tr style="border-top:1px solid #e5e7eb;"><td style="padding:6px 12px;color:#555;font-size:14px;font-weight:600;">Total Charged</td><td style="padding:6px 12px;font-size:14px;font-weight:700;">$${totalChargedUsd}</td></tr>`;
            breakdownRows += `<tr><td colspan="2" style="padding:8px 12px;color:#888;font-size:12px;font-style:italic;">No Stripe fee on failed payments</td></tr>`;
          } else if (payMethod === "card") {
            // Card — customer pays convenience fee which covers Stripe processing
            breakdownRows += `<tr><td style="padding:6px 12px;color:#555;font-size:14px;">Payment Amount</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">$${paymentAmountUsd}</td></tr>`;
            if (discountChecked) {
              breakdownRows += `<tr><td style="padding:6px 12px;color:#555;font-size:14px;">Discount on Invoice</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">Yes</td></tr>`;
            }
            if (convenienceFeeCents > 0) {
              breakdownRows += `<tr><td style="padding:6px 12px;color:#555;font-size:14px;">Card Convenience Fee<br><span style="font-size:11px;color:#16a34a;">Paid by customer</span></td><td style="padding:6px 12px;font-size:14px;font-weight:600;">$${convenienceFeeUsd}</td></tr>`;
            }
            breakdownRows += `<tr style="border-top:1px solid #e5e7eb;"><td style="padding:6px 12px;color:#555;font-size:14px;font-weight:600;">Total Charged to Customer</td><td style="padding:6px 12px;font-size:14px;font-weight:700;">$${totalChargedUsd}</td></tr>`;
            breakdownRows += `<tr><td style="padding:6px 12px;color:#888;font-size:13px;">Est. Stripe Fee<br><span style="font-size:11px;color:#16a34a;">Covered by convenience fee</span></td><td style="padding:6px 12px;font-size:13px;color:#888;">${estimatedStripeFee}</td></tr>`;
            breakdownRows += `<tr><td style="padding:6px 12px;color:#555;font-size:13px;font-weight:600;">Net Deposit to Store</td><td style="padding:6px 12px;font-size:13px;font-weight:700;color:#16a34a;">${estimatedNetDeposit}</td></tr>`;
          } else {
            // ACH — store absorbs Stripe fee
            breakdownRows += `<tr><td style="padding:6px 12px;color:#555;font-size:14px;">Payment Amount</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">$${paymentAmountUsd}</td></tr>`;
            if (discountChecked) {
              breakdownRows += `<tr><td style="padding:6px 12px;color:#555;font-size:14px;">Discount on Invoice</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">Yes</td></tr>`;
            }
            breakdownRows += `<tr style="border-top:1px solid #e5e7eb;"><td style="padding:6px 12px;color:#555;font-size:14px;font-weight:600;">Total Charged</td><td style="padding:6px 12px;font-size:14px;font-weight:700;">$${totalChargedUsd}</td></tr>`;
            breakdownRows += `<tr><td style="padding:6px 12px;color:#d97706;font-size:13px;">Est. Stripe Fee<br><span style="font-size:11px;">Absorbed by store</span></td><td style="padding:6px 12px;font-size:13px;color:#d97706;">-${estimatedStripeFee}</td></tr>`;
            breakdownRows += `<tr><td style="padding:6px 12px;color:#555;font-size:13px;font-weight:600;">Net Deposit to Store</td><td style="padding:6px 12px;font-size:13px;font-weight:700;">${estimatedNetDeposit}</td></tr>`;
          }

          // HTML email template
          const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f3f4f6;font-family:Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f3f4f6;">
<tr><td align="center" style="padding:24px 16px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);">

<!-- NAPA Header -->
<tr><td style="background-color:#0A0094;padding:14px 24px 10px;">
<img src="https://gkk-napa.com/assets/pay-email-logo.png" alt="NAPA Auto Parts" height="48" style="display:block;height:48px;width:auto;">
<div style="color:#ffffff;font-size:13px;margin-top:6px;">${store ? store.replace('NAPA ', '') : ''} Store Payment</div>
</td></tr>

<!-- Status Banner -->
<tr><td style="background-color:${statusBg};border-left:4px solid ${statusColor};padding:16px 24px;">
<span style="font-size:22px;font-weight:700;color:${statusColor};">${statusText}</span>${statusSubtext ? `<span style="font-size:15px;font-weight:600;color:${statusColor};opacity:0.75;"> &middot; ${statusSubtext}</span>` : ''}
<span style="display:block;margin-top:4px;font-size:28px;font-weight:700;color:#111;">$${paymentAmountUsd}</span>
</td></tr>

<!-- Account Details -->
<tr><td style="padding:20px 24px 8px;">
<div style="font-size:13px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Account Details</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:6px;">
<tr><td style="padding:6px 12px;color:#555;font-size:14px;">Company</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">${company || "N/A"}</td></tr>
<tr style="background-color:#f9fafb;"><td style="padding:6px 12px;color:#555;font-size:14px;">Account #</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">${accountNumber || "N/A"}</td></tr>
<tr><td style="padding:6px 12px;color:#555;font-size:14px;">Statement #</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">${statementNumber || "N/A"}</td></tr>
<tr style="background-color:#f9fafb;"><td style="padding:6px 12px;color:#555;font-size:14px;">Store</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">${store || "N/A"}</td></tr>
<tr><td style="padding:6px 12px;color:#555;font-size:14px;">Method</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">${methodLabel}</td></tr>
${dateRows}
</table>
</td></tr>

<!-- Payment Breakdown -->
<tr><td style="padding:16px 24px 8px;">
<div style="font-size:13px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Payment Breakdown</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:6px;">
${breakdownRows}
</table>
</td></tr>

<!-- Customer Contact -->
<tr><td style="padding:16px 24px 8px;">
<div style="font-size:13px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Customer Contact</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:6px;">
<tr><td style="padding:6px 12px;color:#555;font-size:14px;">Email</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">${payerEmail || "Not provided"}</td></tr>
<tr style="background-color:#f9fafb;"><td style="padding:6px 12px;color:#555;font-size:14px;">Phone</td><td style="padding:6px 12px;font-size:14px;font-weight:600;">${payerPhone || "Not provided"}</td></tr>
</table>
</td></tr>

<!-- Stripe Dashboard Button -->
<tr><td align="center" style="padding:24px;">
<a href="${stripeLink}" target="_blank" style="display:inline-block;background-color:#635bff;color:#ffffff;font-size:14px;font-weight:600;text-decoration:none;padding:10px 24px;border-radius:6px;">View in Stripe Dashboard</a>
</td></tr>

<!-- Footer -->
<tr><td style="background-color:#f9fafb;padding:16px 24px;border-top:1px solid #e5e7eb;">
<p style="margin:0;font-size:12px;color:#888;text-align:center;">G&amp;KK NAPA Auto Parts &middot; Automated notification</p>
</td></tr>

</table>
</td></tr>
</table>
</body></html>`;

          // Plain-text fallback
          const text = `${statusText} - $${paymentAmountUsd}

Company: ${company || "N/A"} | Account #: ${accountNumber || "N/A"} | Statement #: ${statementNumber || "N/A"}
Store: ${store || "N/A"} | Method: ${methodLabel}
Payment Amount: $${paymentAmountUsd} | Total Charged: $${totalChargedUsd}
Est. Stripe Fee: ${estimatedStripeFee} | Est. Net Deposit: ${estimatedNetDeposit}
Email: ${payerEmail || "Not provided"} | Phone: ${payerPhone || "Not provided"}

Stripe Dashboard: ${stripeLink}

G&KK NAPA Auto Parts - Automated notification`;

          const emailResponse = await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: {
              Authorization: `Bearer ${env.RESEND_API_KEY}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              from: env.FROM_EMAIL,
              to: env.NOTIFY_EMAILS.split(",").map(s => s.trim()).filter(Boolean),
              reply_to: "payments@gkk-napa.com",
              subject,
              html,
              text,
            }),
          });

          if (!emailResponse.ok) {
            const errBody = await emailResponse.text();
            console.error(JSON.stringify({
              tag: "RESEND_EMAIL_ERROR",
              status: emailResponse.status,
              error: errBody,
              type,
              sessionId,
            }));
          } else {
            console.log(JSON.stringify({
              tag: "RESEND_EMAIL_SENT",
              type,
              sessionId,
              subject,
            }));
          }
        } catch (emailErr) {
          console.error(JSON.stringify({
            tag: "RESEND_EMAIL_EXCEPTION",
            error: emailErr.message,
            type,
            sessionId,
          }));
        }
      }

      // Always return 200 quickly so Stripe doesn't retry
      return new Response(JSON.stringify({ received: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    // Payment summary endpoint (manual trigger for testing)
    // Usage: GET /send-summary?period=week|month&key=YOUR_SUMMARY_KEY
    if (url.pathname === "/send-summary") {
      if (request.method !== "GET" && request.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405 });
      }
      const key = url.searchParams.get("key");
      if (!key || key !== env.SUMMARY_KEY) {
        return new Response(JSON.stringify({ error: "Unauthorized — set SUMMARY_KEY env var and pass ?key=" }), {
          status: 401, headers: { "Content-Type": "application/json" }
        });
      }
      const period = url.searchParams.get("period") || "week";
      return await handleSendSummary(env, period);
    }

    return new Response(JSON.stringify({ error: 'Not found' }), {
      status: 404,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  },

  // Cron trigger handler — configure in Cloudflare Dashboard > Worker > Triggers > Cron
  // Recommended: "0 13 * * 1" = every Monday 7am Central (13:00 UTC)
  async scheduled(event, env, ctx) {
    ctx.waitUntil(handleSendSummary(env, "week"));
  },
};

async function handleCreateCheckoutSession(request, env, corsHeaders) {
  try {
    const body = await request.json();
    const {
      company,
      account_number,
      email,
      phone,
      store,
      statement_number,
      amount_usd,
      discount_checked,
      pay_method
    } = body;

    // Validate required fields
    if (!company || !account_number || !amount_usd || !store || !pay_method) {
      return new Response(
        JSON.stringify({ error: 'Missing required fields: company, account_number, amount_usd, store, pay_method' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Validate pay_method
    if (pay_method !== 'ach' && pay_method !== 'card') {
      return new Response(
        JSON.stringify({ error: 'pay_method must be "ach" or "card"' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Validate store is one of the 4 valid options
    const VALID_STORES = ['NAPA Danville', 'NAPA Cayuga', 'NAPA Rockville', 'NAPA Covington'];
    if (!VALID_STORES.includes(store)) {
      return new Response(
        JSON.stringify({ error: 'Invalid store selection' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Parse and validate payment amount
    const paymentAmountCents = Math.round(parseFloat(amount_usd) * 100);
    if (isNaN(paymentAmountCents) || paymentAmountCents < MIN_CENTS) {
      return new Response(
        JSON.stringify({ error: 'Minimum payment amount is $1.00' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Check max based on payment method
    const maxCentsForMethod = pay_method === 'card' ? CARD_MAX_CENTS : ACH_MAX_CENTS;
    if (paymentAmountCents > maxCentsForMethod) {
      if (pay_method === 'card') {
        return new Response(
          JSON.stringify({ error: 'Card payments are limited to $10,000. Please use Bank (ACH) for larger amounts.' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      } else {
        return new Response(
          JSON.stringify({ error: 'Maximum payment is $50,000. For larger payments, please contact your store.' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }
    }

    // Validate company (required, 1-100 chars)
    const SAFE_TEXT_REGEX = /^[a-zA-Z0-9\s\-_.,#&'()\/]+$/;
    const ACCOUNT_REGEX = /^[a-zA-Z0-9\-_]+$/;
    if (!company || company.length < 1 || company.length > 100) {
      return new Response(
        JSON.stringify({ error: 'Company Name must be 1-100 characters' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }
    if (!SAFE_TEXT_REGEX.test(company)) {
      return new Response(
        JSON.stringify({ error: 'Company Name contains invalid characters' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Validate account_number (required, 1-50 chars, alphanumeric)
    if (!account_number || account_number.length < 1 || account_number.length > 50) {
      return new Response(
        JSON.stringify({ error: 'Account # must be 1-50 characters' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }
    if (!ACCOUNT_REGEX.test(account_number)) {
      return new Response(
        JSON.stringify({ error: 'Account # contains invalid characters' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Validate statement_number (optional, 1-50 chars if provided)
    if (statement_number && (statement_number.length > 50 || !ACCOUNT_REGEX.test(statement_number))) {
      return new Response(
        JSON.stringify({ error: 'Statement # is too long or contains invalid characters' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Discount is a simple boolean flag for reconciliation (no amount calculation)

    // Validate optional contact fields
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return new Response(
        JSON.stringify({ error: 'Invalid email format' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }
    if (phone && !/^[0-9()\-+\s.]+$/.test(phone)) {
      return new Response(
        JSON.stringify({ error: 'Invalid phone format' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Calculate final amount (with convenience fee for card)
    // IMPORTANT: Charge is based on payment amount only, NOT reduced by discount
    // Discount is stored for reconciliation but does not affect the charge
    let totalChargedCents = paymentAmountCents;
    let convenienceFeeCents = 0;

    if (pay_method === 'card') {
      // Gross-up calculation: final = (amount + fixed) / (1 - pct)
      totalChargedCents = Math.ceil((paymentAmountCents + CARD_FIXED_CENTS) / (1 - CARD_PCT));
      convenienceFeeCents = totalChargedCents - paymentAmountCents;
    }

    // Validate total charged doesn't exceed limits (safety check after gross-up)
    // This ensures we never create a Stripe session for an out-of-policy total
    const totalMaxCents = pay_method === 'card' ? CARD_MAX_CENTS + 50000 : ACH_MAX_CENTS; // Allow ~$500 buffer for card fees
    if (totalChargedCents > totalMaxCents) {
      return new Response(
        JSON.stringify({ error: 'Total amount (including fees) exceeds maximum allowed. Please reduce the payment amount or use Bank (ACH).' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Build readable description for Stripe Dashboard
    const descParts = ['Bill Pay', `Company: ${company}`, `ACCT#: ${account_number}`, `Store: ${store}`];
    if (statement_number) descParts.push(`SM#: ${statement_number}`);
    const description = descParts.join(' | ');

    // Build Stripe Checkout Session params
    const sessionParams = {
      mode: 'payment',
      payment_method_types: pay_method === 'ach' ? ['us_bank_account'] : ['card'],
      client_reference_id: account_number,
      phone_number_collection: { enabled: true },
      line_items: [
        {
          price_data: {
            currency: 'usd',
            unit_amount: totalChargedCents,
            product_data: {
              name: `Bill Payment - ${store}`,
              description: `ACCT#: ${account_number}${statement_number ? ` | SM#: ${statement_number}` : ''}`,
            },
          },
          quantity: 1,
        },
      ],
      payment_intent_data: {
        description: description,
        metadata: {
          company,
          account_number,
          store,
          pay_method,
          payment_amount_cents: paymentAmountCents.toString(),
          convenience_fee_cents: convenienceFeeCents.toString(),
          total_charged_cents: totalChargedCents.toString(),
        },
      },
      success_url: `${env.SUCCESS_URL || 'https://gkk-napa.com/pay/success'}?store=${encodeURIComponent(store)}&method=${encodeURIComponent(pay_method)}`,
      cancel_url: env.CANCEL_URL || 'https://gkk-napa.com/pay/cancel',
    };

    // Add optional fields to payment_intent metadata
    if (statement_number) sessionParams.payment_intent_data.metadata.statement_number = statement_number;
    if (discount_checked) sessionParams.payment_intent_data.metadata.discount_checked = "true";
    if (email) sessionParams.payment_intent_data.metadata.customer_email = email;
    if (phone) sessionParams.payment_intent_data.metadata.customer_phone = phone;

    // Also add metadata at session level (for webhook access)
    sessionParams.metadata = {
      company,
      account_number,
      store,
      pay_method,
      payment_amount_cents: paymentAmountCents.toString(),
      convenience_fee_cents: convenienceFeeCents.toString(),
      total_charged_cents: totalChargedCents.toString(),
    };
    if (statement_number) sessionParams.metadata.statement_number = statement_number;
    if (discount_checked) sessionParams.metadata.discount_checked = "true";
    if (email) sessionParams.metadata.customer_email = email;
    if (phone) sessionParams.metadata.customer_phone = phone;

    // Add customer email if provided
    if (email) {
      sessionParams.customer_email = email;
    }

    // For ACH, configure payment method options
    if (pay_method === 'ach') {
      sessionParams.payment_method_options = {
        us_bank_account: {
          financial_connections: {
            permissions: ['payment_method'],
          },
          verification_method: 'automatic',
        },
      };
    }

    // Create Stripe Checkout Session
    const stripeResponse = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: encodeStripeParams(sessionParams),
    });

    const session = await stripeResponse.json();

    if (!stripeResponse.ok) {
      console.error('Stripe error:', session);
      return new Response(
        JSON.stringify({ error: session.error?.message || 'Failed to create checkout session' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Return session URL and fee info
    return new Response(
      JSON.stringify({
        url: session.url,
        payment_amount_usd: (paymentAmountCents / 100).toFixed(2),
        convenience_fee_usd: (convenienceFeeCents / 100).toFixed(2),
        final_amount_usd: (totalChargedCents / 100).toFixed(2),
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  } catch (err) {
    console.error('Error:', err);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
}

/**
 * Encode nested object as Stripe's x-www-form-urlencoded format
 * e.g., { line_items: [{ price_data: { currency: 'usd' } }] }
 *       becomes "line_items[0][price_data][currency]=usd"
 */
function encodeStripeParams(obj, prefix = '') {
  const pairs = [];

  for (const key in obj) {
    if (obj[key] === undefined || obj[key] === null) continue;

    const fullKey = prefix ? `${prefix}[${key}]` : key;

    if (Array.isArray(obj[key])) {
      obj[key].forEach((item, index) => {
        if (typeof item === 'object') {
          pairs.push(encodeStripeParams(item, `${fullKey}[${index}]`));
        } else {
          pairs.push(`${encodeURIComponent(`${fullKey}[${index}]`)}=${encodeURIComponent(item)}`);
        }
      });
    } else if (typeof obj[key] === 'object') {
      pairs.push(encodeStripeParams(obj[key], fullKey));
    } else {
      pairs.push(`${encodeURIComponent(fullKey)}=${encodeURIComponent(obj[key])}`);
    }
  }

  return pairs.join('&');
}

// ============ Weekly/Monthly Payment Summary ============

// Format cents as USD string with commas
function fmtUsd(cents) {
  const abs = Math.abs(cents);
  const dollars = (abs / 100).toFixed(2);
  const parts = dollars.split('.');
  parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return (cents < 0 ? '-$' : '$') + parts.join('.');
}

// Get date range for the requested period
function getPeriodRange(period) {
  const now = new Date();

  if (period === "month") {
    const since = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
    const monthName = now.toLocaleDateString('en-US', { month: 'long', year: 'numeric', timeZone: 'America/Chicago' });
    return {
      sinceUnix: Math.floor(since.getTime() / 1000),
      untilUnix: Math.floor(now.getTime() / 1000),
      label: monthName,
      periodType: "Monthly",
    };
  }

  // Default: last 7 days
  const since = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const startStr = since.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'America/Chicago' });
  const endStr = now.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'America/Chicago' });
  return {
    sinceUnix: Math.floor(since.getTime() / 1000),
    untilUnix: Math.floor(now.getTime() / 1000),
    label: `${startStr} – ${endStr}`,
    periodType: "Weekly",
  };
}

// Fetch all charges from Stripe for a date range (handles pagination)
async function fetchAllCharges(stripeKey, sinceUnix, untilUnix) {
  const charges = [];
  let startingAfter = null;

  for (let page = 0; page < 20; page++) { // safety limit: 2000 charges max
    let url = `https://api.stripe.com/v1/charges?created[gte]=${sinceUnix}&created[lte]=${untilUnix}&limit=100&expand[]=data.balance_transaction`;
    if (startingAfter) url += `&starting_after=${startingAfter}`;

    const resp = await fetch(url, {
      headers: { 'Authorization': `Bearer ${stripeKey}` }
    });
    const data = await resp.json();

    if (!data.data || data.data.length === 0) break;
    charges.push(...data.data);

    if (!data.has_more) break;
    startingAfter = data.data[data.data.length - 1].id;
  }

  return charges;
}

// Build summary email HTML
function buildSummaryHtml(d) {
  let failedHtml = '';
  if (d.failedCount > 0) {
    let failedRows = '';
    for (const f of d.failedDetails.slice(0, 10)) {
      failedRows += `<tr><td style="padding:4px 12px;font-size:13px;color:#dc2626;">${f.company}</td><td style="padding:4px 12px;font-size:13px;color:#dc2626;">ACCT# ${f.account}</td><td style="padding:4px 12px;font-size:13px;color:#dc2626;text-align:right;">${fmtUsd(f.amount)}</td></tr>`;
    }
    failedHtml = `
<tr><td style="padding:16px 24px 8px;">
<div style="font-size:13px;font-weight:700;color:#dc2626;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Failed Payments (${d.failedCount})</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #fecaca;border-radius:6px;background-color:#fef2f2;">
${failedRows}
</table>
</td></tr>`;
  }

  // Store breakdown by location
  let storeBreakdownHtml = '';
  if (d.storeBreakdown && Object.keys(d.storeBreakdown).length > 0) {
    let storeRows = '';
    const stores = Object.entries(d.storeBreakdown).sort((a, b) => b[1].amount - a[1].amount);
    let alt = false;
    for (const [store, info] of stores) {
      const bg = alt ? ' style="background-color:#f9fafb;"' : '';
      storeRows += `<tr${bg}><td style="padding:6px 12px;color:#555;font-size:14px;">${store}</td><td style="padding:6px 12px;font-size:14px;text-align:center;">${info.count}</td><td style="padding:6px 12px;font-size:14px;font-weight:600;text-align:right;">${fmtUsd(info.amount)}</td></tr>`;
      alt = !alt;
    }
    storeBreakdownHtml = `
<tr><td style="padding:16px 24px 8px;">
<div style="font-size:13px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">By Store</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:6px;">
<tr style="background-color:#f3f4f6;"><td style="padding:4px 12px;font-size:11px;font-weight:700;color:#888;">STORE</td><td style="padding:4px 12px;font-size:11px;font-weight:700;color:#888;text-align:center;">COUNT</td><td style="padding:4px 12px;font-size:11px;font-weight:700;color:#888;text-align:right;">AMOUNT</td></tr>
${storeRows}
</table>
</td></tr>`;
  }

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f3f4f6;font-family:Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f3f4f6;">
<tr><td align="center" style="padding:24px 16px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);">

<!-- NAPA Header -->
<tr><td style="background-color:#0A0094;padding:14px 24px 10px;">
<img src="https://gkk-napa.com/assets/pay-email-logo.png" alt="NAPA Auto Parts" height="48" style="display:block;height:48px;width:auto;">
<div style="color:#ffffff;font-size:13px;margin-top:6px;">G&amp;KK Store Payments</div>
</td></tr>

<!-- Title Banner -->
<tr><td style="background-color:#f8fafc;border-left:4px solid #0A0094;padding:16px 24px;">
<span style="font-size:20px;font-weight:700;color:#0A0094;">${d.periodType} Payment Summary</span>
<span style="display:block;margin-top:4px;font-size:14px;color:#555;">${d.label}</span>
</td></tr>

<!-- Overview -->
<tr><td style="padding:20px 24px 8px;">
<div style="font-size:13px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Overview</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:6px;">
<tr><td style="padding:10px 12px;color:#111;font-size:15px;font-weight:700;">Total Payments</td><td style="padding:10px 12px;font-size:15px;font-weight:700;text-align:right;">${d.totalCount} &nbsp;&middot;&nbsp; ${fmtUsd(d.totalAmountCents)}</td></tr>
<tr style="background-color:#f9fafb;"><td style="padding:6px 12px;color:#555;font-size:14px;">\u{1F3E6} ACH Payments</td><td style="padding:6px 12px;font-size:14px;font-weight:600;text-align:right;">${d.achCount} &nbsp;&middot;&nbsp; ${fmtUsd(d.achAmountCents)}</td></tr>
<tr><td style="padding:6px 12px;color:#555;font-size:14px;">\u{1F4B3} Card Payments</td><td style="padding:6px 12px;font-size:14px;font-weight:600;text-align:right;">${d.cardCount} &nbsp;&middot;&nbsp; ${fmtUsd(d.cardAmountCents)}</td></tr>
</table>
</td></tr>

<!-- Store Costs (ACH) -->
<tr><td style="padding:16px 24px 8px;">
<div style="font-size:13px;font-weight:700;color:#d97706;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Store Costs (ACH)</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #fde68a;border-radius:6px;background-color:#fffbeb;">
<tr><td style="padding:8px 12px;color:#92400e;font-size:14px;">Stripe Fees Absorbed</td><td style="padding:8px 12px;font-size:14px;font-weight:700;color:#d97706;text-align:right;">-${fmtUsd(d.achFeeCents)}</td></tr>
<tr><td colspan="2" style="padding:4px 12px 8px;font-size:11px;color:#92400e;">These fees come out of ACH payment deposits</td></tr>
</table>
</td></tr>

<!-- Customer Fees (Card) -->
<tr><td style="padding:16px 24px 8px;">
<div style="font-size:13px;font-weight:700;color:#16a34a;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Customer Fees (Card)</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #bbf7d0;border-radius:6px;background-color:#f0fdf4;">
<tr><td style="padding:8px 12px;color:#166534;font-size:14px;">Convenience Fees Collected</td><td style="padding:8px 12px;font-size:14px;font-weight:700;color:#16a34a;text-align:right;">${fmtUsd(d.cardConvFeeCents)}</td></tr>
<tr><td style="padding:4px 12px;color:#166534;font-size:13px;">Stripe Processing Covered</td><td style="padding:4px 12px;font-size:13px;color:#16a34a;text-align:right;">${fmtUsd(d.cardFeeCents)}</td></tr>
<tr><td colspan="2" style="padding:4px 12px 8px;font-size:11px;color:#166534;">Customers pay these fees — no cost to store</td></tr>
</table>
</td></tr>

<!-- Net Deposits -->
<tr><td style="padding:16px 24px 8px;">
<div style="font-size:13px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Net Deposits</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:6px;">
<tr style="background-color:#f0fdf4;"><td style="padding:10px 12px;color:#111;font-size:16px;font-weight:700;">Total Net to Store</td><td style="padding:10px 12px;font-size:16px;font-weight:700;text-align:right;">${fmtUsd(d.totalNetCents)}</td></tr>
<tr><td style="padding:6px 12px;color:#555;font-size:13px;">ACH Net</td><td style="padding:6px 12px;font-size:13px;text-align:right;">${fmtUsd(d.achNetCents)}</td></tr>
<tr style="background-color:#f9fafb;"><td style="padding:6px 12px;color:#555;font-size:13px;">Card Net</td><td style="padding:6px 12px;font-size:13px;text-align:right;">${fmtUsd(d.cardNetCents)}</td></tr>
</table>
</td></tr>

${storeBreakdownHtml}
${failedHtml}

<!-- Stripe Dashboard Button -->
<tr><td align="center" style="padding:24px;">
<a href="https://dashboard.stripe.com/payments" target="_blank" style="display:inline-block;background-color:#635bff;color:#ffffff;font-size:14px;font-weight:600;text-decoration:none;padding:10px 24px;border-radius:6px;">View All in Stripe Dashboard</a>
</td></tr>

<!-- Footer -->
<tr><td style="background-color:#f9fafb;padding:16px 24px;border-top:1px solid #e5e7eb;">
<p style="margin:0;font-size:12px;color:#888;text-align:center;">G&amp;KK NAPA Auto Parts &middot; ${d.periodType} summary &middot; Automated notification</p>
</td></tr>

</table>
</td></tr>
</table>
</body></html>`;
}

// Main summary handler — fetches Stripe data and sends summary email
async function handleSendSummary(env, period) {
  if (!env.STRIPE_SECRET_KEY || !env.RESEND_API_KEY || !env.FROM_EMAIL || !env.NOTIFY_EMAILS) {
    return new Response(JSON.stringify({ error: "Missing required env vars (STRIPE_SECRET_KEY, RESEND_API_KEY, FROM_EMAIL, NOTIFY_EMAILS)" }), {
      status: 500, headers: { "Content-Type": "application/json" }
    });
  }

  const { sinceUnix, untilUnix, label, periodType } = getPeriodRange(period);

  // Fetch all charges from Stripe for this period
  const charges = await fetchAllCharges(env.STRIPE_SECRET_KEY, sinceUnix, untilUnix);

  // Aggregate data
  let achCount = 0, achAmountCents = 0, achFeeCents = 0, achNetCents = 0;
  let cardCount = 0, cardAmountCents = 0, cardFeeCents = 0, cardConvFeeCents = 0, cardNetCents = 0;
  let failedCount = 0, failedAmountCents = 0;
  const failedDetails = [];
  const storeBreakdown = {};

  for (const charge of charges) {
    const payMethod = charge.metadata?.pay_method ||
      (charge.payment_method_details?.type === "us_bank_account" ? "ach" : "card");
    const paymentAmountCents = parseInt(charge.metadata?.payment_amount_cents || charge.amount, 10);
    const fee = charge.balance_transaction?.fee || 0;
    const convFee = parseInt(charge.metadata?.convenience_fee_cents || "0", 10);
    const store = charge.metadata?.store || "Unknown";

    // Handle failed or refunded charges
    if (charge.status === "failed" || charge.refunded) {
      failedCount++;
      failedAmountCents += paymentAmountCents;
      failedDetails.push({
        account: charge.metadata?.account_number || "N/A",
        company: charge.metadata?.company || "N/A",
        amount: paymentAmountCents,
        store,
      });
      continue;
    }

    if (charge.status !== "succeeded") continue; // skip pending

    // Track by store
    if (!storeBreakdown[store]) storeBreakdown[store] = { count: 0, amount: 0 };
    storeBreakdown[store].count++;
    storeBreakdown[store].amount += paymentAmountCents;

    if (payMethod === "ach") {
      achCount++;
      achAmountCents += paymentAmountCents;
      achFeeCents += fee;
      achNetCents += (charge.amount - fee);
    } else {
      cardCount++;
      cardAmountCents += paymentAmountCents;
      cardFeeCents += fee;
      cardConvFeeCents += convFee;
      cardNetCents += (charge.amount - fee);
    }
  }

  const totalCount = achCount + cardCount;
  const totalAmountCents = achAmountCents + cardAmountCents;
  const totalNetCents = achNetCents + cardNetCents;

  // Build and send email
  const html = buildSummaryHtml({
    periodType, label,
    totalCount, totalAmountCents, totalNetCents,
    achCount, achAmountCents, achFeeCents, achNetCents,
    cardCount, cardAmountCents, cardFeeCents, cardConvFeeCents, cardNetCents,
    failedCount, failedAmountCents, failedDetails,
    storeBreakdown,
  });

  const subject = `\u{1F4CA} ${periodType} Payment Summary – ${label}`;

  const emailResp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: env.FROM_EMAIL,
      to: env.NOTIFY_EMAILS.split(",").map(s => s.trim()).filter(Boolean),
      reply_to: "payments@gkk-napa.com",
      subject,
      html,
    }),
  });

  if (!emailResp.ok) {
    const err = await emailResp.text();
    console.error(JSON.stringify({ tag: "SUMMARY_EMAIL_ERROR", error: err, period }));
    return new Response(JSON.stringify({ error: err }), {
      status: 500, headers: { "Content-Type": "application/json" }
    });
  }

  const result = await emailResp.json();
  console.log(JSON.stringify({ tag: "SUMMARY_EMAIL_SENT", period, label, emailId: result.id }));

  return new Response(JSON.stringify({ ok: true, email_id: result.id, period, label, charges_processed: charges.length }), {
    headers: { "Content-Type": "application/json" }
  });
}
