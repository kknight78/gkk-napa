/**
 * GK&K NAPA Bill Pay - Cloudflare Worker
 *
 * Creates Stripe Checkout Sessions for ACH and Card payments.
 * Card payments include a convenience fee (gross-up calculation).
 *
 * Environment Variables Required:
 *   STRIPE_SECRET_KEY - Stripe secret key (test or live)
 *   SUCCESS_URL - Redirect URL after successful payment
 *   CANCEL_URL - Redirect URL if user cancels
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
      },
      metadata: {
        invoice_ref,
        store,
        entered_amount_cents: amountCents.toString(),
        convenience_fee_cents: convenienceFeeCents.toString(),
        pay_method,
      },
      success_url: env.SUCCESS_URL || 'https://gkk-napa.com/pay/success',
      cancel_url: env.CANCEL_URL || 'https://gkk-napa.com/pay/cancel',
    };

    // Add optional metadata for reconciliation
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
