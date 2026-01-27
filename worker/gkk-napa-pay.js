/**
 * GK&K NAPA Bill Pay - Cloudflare Worker
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

// Allowed origins for CORS
const allowedOrigins = new Set([
  "https://gkk-napa.com",
  "https://www.gkk-napa.com",
  // Cloudflare Pages preview domain:
  "https://gkk-napa.pages.dev",
]);

// Get CORS headers based on request origin
function getCorsHeaders(request) {
  const origin = request.headers.get("Origin");
  return {
    "Access-Control-Allow-Origin": allowedOrigins.has(origin) ? origin : "https://gkk-napa.com",
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

      // Checkout Session fields (works for completed + async_* events)
      const sessionId = obj.id;
      const invoiceRef = obj.client_reference_id || obj.metadata?.invoice_ref;
      const store = obj.metadata?.store;
      const payMethod = obj.metadata?.pay_method;
      const paymentStatus = obj.payment_status; // paid/unpaid/no_payment_required
      const amountTotal = typeof obj.amount_total === "number" ? (obj.amount_total / 100).toFixed(2) : undefined;

      const payerEmail = obj.customer_details?.email || obj.metadata?.payer_email;
      // Prefer phone from our form (metadata) over Stripe Checkout's collected phone
      const payerPhone = obj.metadata?.payer_phone || obj.customer_details?.phone;

      const isSuccess = (type === "checkout.session.completed" || type === "checkout.session.async_payment_succeeded");
      const isFailure = (type === "checkout.session.async_payment_failed" || type === "checkout.session.expired");

      console.log(JSON.stringify({
        tag: "STRIPE_WEBHOOK",
        type,
        isSuccess,
        isFailure,
        sessionId,
        invoiceRef,
        store,
        payMethod,
        paymentStatus,
        amountTotal,
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
          // Build email subject and body
          let subject, statusEmoji, statusText;

          if (type === "checkout.session.completed") {
            statusEmoji = "✅";
            statusText = "Payment Received";
            subject = `${statusEmoji} Payment Received - ${store} - $${amountTotal}`;
          } else if (type === "checkout.session.async_payment_succeeded") {
            statusEmoji = "✅";
            statusText = "ACH Payment Cleared";
            subject = `${statusEmoji} ACH Cleared - ${store} - $${amountTotal}`;
          } else if (type === "checkout.session.async_payment_failed") {
            statusEmoji = "❌";
            statusText = "ACH Payment Failed";
            subject = `${statusEmoji} ACH FAILED - ${store} - $${amountTotal}`;
          }

          // Stripe dashboard link (use payment intent if available, else session)
          const paymentIntentId = obj.payment_intent;
          const stripeLink = paymentIntentId
            ? `https://dashboard.stripe.com/payments/${paymentIntentId}`
            : `https://dashboard.stripe.com/checkout/sessions/${sessionId}`;

          const text = `
${statusText}

Store: ${store || "N/A"}
Invoice/Ref: ${invoiceRef || "N/A"}
Amount: $${amountTotal || "0.00"} USD
Method: ${payMethod === "ach" ? "Bank (ACH)" : payMethod === "card" ? "Credit Card" : payMethod || "N/A"}
Status: ${paymentStatus || "N/A"}

Customer Contact:
  Email: ${payerEmail || "Not provided"}
  Phone: ${payerPhone || "Not provided"}

View in Stripe Dashboard:
${stripeLink}

---
This is an automated notification from GK&K NAPA Bill Pay.
`.trim();

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

    return new Response(JSON.stringify({ error: 'Not found' }), {
      status: 404,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  },
};

async function handleCreateCheckoutSession(request, env, corsHeaders) {
  try {
    const body = await request.json();
    const { amount_usd, invoice_ref, store, pay_method, email, phone, company, po_number } = body;

    // Validate required fields
    if (!amount_usd || !invoice_ref || !store || !pay_method) {
      return new Response(
        JSON.stringify({ error: 'Missing required fields: amount_usd, invoice_ref, store, pay_method' }),
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

    // Parse amount
    const amountCents = Math.round(parseFloat(amount_usd) * 100);
    if (isNaN(amountCents) || amountCents <= 0) {
      return new Response(
        JSON.stringify({ error: 'Invalid amount' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Calculate final amount (with convenience fee for card)
    let finalAmountCents = amountCents;
    let convenienceFeeCents = 0;

    if (pay_method === 'card') {
      // Gross-up calculation: final = (amount + fixed) / (1 - pct)
      finalAmountCents = Math.ceil((amountCents + CARD_FIXED_CENTS) / (1 - CARD_PCT));
      convenienceFeeCents = finalAmountCents - amountCents;
    }

    // Build readable description for Stripe Dashboard
    const descParts = ['Bill Pay', `Invoice: ${invoice_ref}`, `Store: ${store}`];
    if (company) descParts.push(`Company: ${company}`);
    if (po_number) descParts.push(`PO: ${po_number}`);
    const description = descParts.join(' • ');

    // Build Stripe Checkout Session params
    const sessionParams = {
      mode: 'payment',
      payment_method_types: pay_method === 'ach' ? ['us_bank_account'] : ['card'],
      client_reference_id: invoice_ref,
      phone_number_collection: { enabled: true },
      line_items: [
        {
          price_data: {
            currency: 'usd',
            unit_amount: finalAmountCents,
            product_data: {
              name: `Bill Payment - ${store}`,
              description: `Invoice/Ref: ${invoice_ref}`,
            },
          },
          quantity: 1,
        },
      ],
      payment_intent_data: {
        description: description,
        metadata: {
          invoice_ref,
          store,
          entered_amount_cents: amountCents.toString(),
          convenience_fee_cents: convenienceFeeCents.toString(),
          pay_method,
        },
      },
      success_url: env.SUCCESS_URL || 'https://gkk-napa.com/pay/success',
      cancel_url: env.CANCEL_URL || 'https://gkk-napa.com/pay/cancel',
    };

    // Add optional metadata for reconciliation (on payment intent)
    if (email) sessionParams.payment_intent_data.metadata.payer_email = email;
    if (phone) sessionParams.payment_intent_data.metadata.payer_phone = phone;
    if (company) sessionParams.payment_intent_data.metadata.company = company;
    if (po_number) sessionParams.payment_intent_data.metadata.po_number = po_number;

    // Also add metadata at session level (for webhook access)
    sessionParams.metadata = {
      invoice_ref,
      store,
      pay_method,
    };
    if (email) sessionParams.metadata.payer_email = email;
    if (phone) sessionParams.metadata.payer_phone = phone;
    if (company) sessionParams.metadata.company = company;
    if (po_number) sessionParams.metadata.po_number = po_number;

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
        final_amount_usd: (finalAmountCents / 100).toFixed(2),
        convenience_fee_usd: (convenienceFeeCents / 100).toFixed(2),
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
