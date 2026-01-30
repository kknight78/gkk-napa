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
      const discountAmountCents = parseInt(obj.metadata?.discount_amount_cents || "0", 10);
      const convenienceFeeCents = parseInt(obj.metadata?.convenience_fee_cents || "0", 10);
      const totalChargedCents = parseInt(obj.metadata?.total_charged_cents || "0", 10);
      // discount_deadline removed - discount now auto-calculated as 10%

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
        discountAmountCents,
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
          const discountAmountUsd = (discountAmountCents / 100).toFixed(2);
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

          // Build email subject and body
          let subject, statusEmoji, statusText;

          if (type === "checkout.session.completed") {
            statusEmoji = "✅";
            statusText = "Payment Received";
            const feeNote = payMethod === "card" && convenienceFeeCents > 0 ? ` (plus $${convenienceFeeUsd} card fee)` : "";
            subject = `${statusEmoji} Payment Received - ${store} - $${paymentAmountUsd}${feeNote}`;
          } else if (type === "checkout.session.async_payment_succeeded") {
            statusEmoji = "✅";
            statusText = "ACH Payment Cleared";
            subject = `${statusEmoji} ACH Cleared - ${store} - $${paymentAmountUsd}`;
          } else if (type === "checkout.session.async_payment_failed") {
            statusEmoji = "❌";
            statusText = "ACH Payment Failed";
            subject = `${statusEmoji} ACH FAILED - ${store} - ACCT# ${accountNumber || 'N/A'} - DO NOT CREDIT`;
          }

          // Stripe dashboard link
          const paymentIntentId = obj.payment_intent;
          const stripeLink = paymentIntentId
            ? `https://dashboard.stripe.com/payments/${paymentIntentId}`
            : `https://dashboard.stripe.com/checkout/sessions/${sessionId}`;

          // Build payment breakdown section
          let paymentBreakdown = `
PAYMENT BREAKDOWN
─────────────────────────────
Payment amount (applied to account):  $${paymentAmountUsd}`;

          if (discountAmountCents > 0) {
            paymentBreakdown += `
10% early-pay discount claimed:       $${discountAmountUsd}`;
          }

          if (payMethod === "card" && convenienceFeeCents > 0) {
            paymentBreakdown += `
Card convenience fee:                 $${convenienceFeeUsd}`;
          }

          paymentBreakdown += `
─────────────────────────────
Total charged to customer:            $${totalChargedUsd}

Estimated Stripe Processing Fee:      ${estimatedStripeFee}
Estimated Net Deposit to You:         ${estimatedNetDeposit}`;

          const text = `
${statusText}

ACCOUNT DETAILS
─────────────────────────────
Company:            ${company || "N/A"}
Account # (ACCT#):  ${accountNumber || "N/A"}
Statement # (SM#):  ${statementNumber || "N/A"}
Store:              ${store || "N/A"}
Method:             ${payMethod === "ach" ? "Bank (ACH)" : payMethod === "card" ? "Credit Card" : payMethod || "N/A"}
${paymentBreakdown}

CUSTOMER CONTACT
─────────────────────────────
Email: ${payerEmail || "Not provided"}
Phone: ${payerPhone || "Not provided"}

View in Stripe Dashboard:
${stripeLink}

---
This is an automated notification from G&KK NAPA Bill Pay.
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
    const {
      company,
      account_number,
      email,
      phone,
      store,
      statement_number,
      amount_usd,
      discount_amount_usd,
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

    // Validate discount fields
    let discountAmountCents = 0;
    if (discount_amount_usd) {
      discountAmountCents = Math.round(parseFloat(discount_amount_usd) * 100);
      if (isNaN(discountAmountCents) || discountAmountCents < 0) {
        return new Response(
          JSON.stringify({ error: 'Discount amount must be a positive number' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }
      if (discountAmountCents > paymentAmountCents) {
        return new Response(
          JSON.stringify({ error: 'Discount amount cannot exceed payment amount' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }
    }

    // discount_deadline removed - discount is now auto-calculated as 10% on frontend

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
    if (discountAmountCents > 0) sessionParams.payment_intent_data.metadata.discount_amount_cents = discountAmountCents.toString();
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
    if (discountAmountCents > 0) sessionParams.metadata.discount_amount_cents = discountAmountCents.toString();
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
