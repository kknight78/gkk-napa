/**
 * G&KK NAPA Careers - Cloudflare Worker
 *
 * Receives job application submissions and sends email notifications.
 * Manages open positions via KV storage with admin endpoints.
 *
 * Environment Variables Required:
 *   RESEND_API_KEY - Resend API key for email notifications
 *   FROM_EMAIL - Sender email address (e.g., careers@gkk-napa.com)
 *   NOTIFY_EMAILS - Comma-separated recipient emails (manager notifications)
 *   ADMIN_PASSWORD - Password for admin endpoints
 *
 * KV Namespace Binding:
 *   POSITIONS_KV - KV namespace for storing open positions
 */

const KV_KEY = "positions";

// Allowed origins for CORS
const allowedOrigins = new Set([
  "https://gkk-napa.com",
  "https://www.gkk-napa.com",
  "https://gkk-napa.pages.dev",
]);

function isAllowedOrigin(origin) {
  if (!origin) return false;
  if (allowedOrigins.has(origin)) return true;
  if (origin.endsWith(".gkk-napa.pages.dev")) return true;
  return false;
}

function getCorsHeaders(request) {
  const origin = request.headers.get("Origin");
  return {
    "Access-Control-Allow-Origin": isAllowedOrigin(origin) ? origin : "https://gkk-napa.com",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

const VALID_LOCATIONS = ["danville-il", "cayuga-in", "rockville-in", "covington-in"];

const LOCATION_DISPLAY = {
  "danville-il": "Danville, IL",
  "cayuga-in": "Cayuga, IN",
  "rockville-in": "Rockville, IN",
  "covington-in": "Covington, IN",
};

const NAME_REGEX = /^[a-zA-Z\s\-'.]+$/;
const PHONE_REGEX = /^[0-9()\-+\s.]+$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SAFE_TEXT_REGEX = /^[a-zA-Z0-9\s\-_.,#&'()\/!?:;@$%+"]+$/;

// ─── Auth helper ───
function checkAdmin(request, env) {
  const auth = request.headers.get("Authorization");
  if (!auth || !env.ADMIN_PASSWORD) return false;
  const expected = `Bearer ${env.ADMIN_PASSWORD}`;
  return auth === expected;
}

// ─── KV helpers ───
async function getPositions(env) {
  const data = await env.POSITIONS_KV.get(KV_KEY, "json");
  return data || [];
}

async function savePositions(env, positions) {
  await env.POSITIONS_KV.put(KV_KEY, JSON.stringify(positions));
}

export default {
  async fetch(request, env) {
    const corsHeaders = getCorsHeaders(request);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // ─── Public: GET /positions ───
    if (request.method === "GET" && path === "/positions") {
      const positions = await getPositions(env);
      // Only return active positions to the public
      const active = positions.filter(p => p.active);
      return new Response(JSON.stringify(active), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ─── Admin: GET /admin/positions (all, including inactive) ───
    if (request.method === "GET" && path === "/admin/positions") {
      if (!checkAdmin(request, env)) {
        return jsonError(corsHeaders, "Unauthorized", 401);
      }
      const positions = await getPositions(env);
      return new Response(JSON.stringify(positions), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ─── Admin: POST /admin/positions (add or update) ───
    if (request.method === "POST" && path === "/admin/positions") {
      if (!checkAdmin(request, env)) {
        return jsonError(corsHeaders, "Unauthorized", 401);
      }
      try {
        const body = await request.json();
        const { title, description } = body;

        if (!title || !title.trim()) {
          return jsonError(corsHeaders, "Title is required.", 400);
        }
        if (title.trim().length > 100) {
          return jsonError(corsHeaders, "Title must be under 100 characters.", 400);
        }
        if (description && description.length > 500) {
          return jsonError(corsHeaders, "Description must be under 500 characters.", 400);
        }

        const positions = await getPositions(env);
        const newPosition = {
          id: crypto.randomUUID(),
          title: title.trim(),
          description: (description || "").trim(),
          active: true,
          created: new Date().toISOString(),
        };
        positions.push(newPosition);
        await savePositions(env, positions);

        return new Response(JSON.stringify(newPosition), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      } catch {
        return jsonError(corsHeaders, "Invalid request body.", 400);
      }
    }

    // ─── Admin: POST /admin/positions/:id/toggle ───
    if (request.method === "POST" && path.match(/^\/admin\/positions\/[^/]+\/toggle$/)) {
      if (!checkAdmin(request, env)) {
        return jsonError(corsHeaders, "Unauthorized", 401);
      }
      const id = path.split("/")[3];
      const positions = await getPositions(env);
      const pos = positions.find(p => p.id === id);
      if (!pos) return jsonError(corsHeaders, "Position not found.", 404);
      pos.active = !pos.active;
      await savePositions(env, positions);
      return new Response(JSON.stringify(pos), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ─── Admin: DELETE /admin/positions/:id ───
    if (request.method === "DELETE" && path.match(/^\/admin\/positions\/[^/]+$/)) {
      if (!checkAdmin(request, env)) {
        return jsonError(corsHeaders, "Unauthorized", 401);
      }
      const id = path.split("/")[3];
      let positions = await getPositions(env);
      const before = positions.length;
      positions = positions.filter(p => p.id !== id);
      if (positions.length === before) {
        return jsonError(corsHeaders, "Position not found.", 404);
      }
      await savePositions(env, positions);
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ─── Admin: POST /admin/login (verify password) ───
    if (request.method === "POST" && path === "/admin/login") {
      if (!checkAdmin(request, env)) {
        return jsonError(corsHeaders, "Invalid password.", 401);
      }
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ─── Public: POST /submit-application ───
    if (request.method === "POST" && path === "/submit-application") {
      return handleSubmitApplication(request, env, corsHeaders);
    }

    return new Response(JSON.stringify({ error: "Not found" }), {
      status: 404,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  },
};

async function handleSubmitApplication(request, env, corsHeaders) {
  try {
    const body = await request.json();
    const {
      full_name, phone, email, address, position,
      locations, availability, schedule,
      work_history_1, work_history_2,
      references, additional,
    } = body;

    // ─── Required field checks ───
    if (!full_name || !phone || !address || !position || !locations || !availability || !work_history_1) {
      return jsonError(corsHeaders, "Missing required fields.", 400);
    }

    // ─── Validate position against KV (must be an active position title) ───
    const activePositions = (await getPositions(env)).filter(p => p.active);
    const validTitles = activePositions.map(p => p.title);
    if (!validTitles.includes(position)) {
      return jsonError(corsHeaders, "Invalid or closed position.", 400);
    }

    // ─── Validate full_name ───
    const trimmedName = full_name.trim();
    if (trimmedName.length < 2 || trimmedName.length > 100) {
      return jsonError(corsHeaders, "Full name must be 2-100 characters.", 400);
    }
    if (!NAME_REGEX.test(trimmedName)) {
      return jsonError(corsHeaders, "Full name contains invalid characters.", 400);
    }

    // ─── Validate phone ───
    const trimmedPhone = phone.trim();
    if (trimmedPhone.length < 7 || trimmedPhone.length > 20) {
      return jsonError(corsHeaders, "Phone number must be 7-20 characters.", 400);
    }
    if (!PHONE_REGEX.test(trimmedPhone)) {
      return jsonError(corsHeaders, "Phone number contains invalid characters.", 400);
    }

    // ─── Validate email (optional) ───
    const trimmedEmail = email ? email.trim() : "";
    if (trimmedEmail && !EMAIL_REGEX.test(trimmedEmail)) {
      return jsonError(corsHeaders, "Invalid email format.", 400);
    }

    // ─── Validate address ───
    const trimmedAddress = address.trim();
    if (trimmedAddress.length < 5 || trimmedAddress.length > 200) {
      return jsonError(corsHeaders, "Address must be 5-200 characters.", 400);
    }
    if (!SAFE_TEXT_REGEX.test(trimmedAddress)) {
      return jsonError(corsHeaders, "Address contains invalid characters.", 400);
    }

    // ─── Validate locations ───
    if (!Array.isArray(locations) || locations.length === 0) {
      return jsonError(corsHeaders, "Please select at least one location.", 400);
    }
    for (const loc of locations) {
      if (!VALID_LOCATIONS.includes(loc)) {
        return jsonError(corsHeaders, "Invalid location selection.", 400);
      }
    }

    // ─── Validate availability ───
    const VALID_AVAILABILITY = ["Full-Time", "Part-Time", "Either"];
    if (!VALID_AVAILABILITY.includes(availability)) {
      return jsonError(corsHeaders, "Invalid availability selection.", 400);
    }

    // ─── Validate schedule (optional) ───
    const trimmedSchedule = schedule ? schedule.trim() : "";
    if (trimmedSchedule && trimmedSchedule.length > 200) {
      return jsonError(corsHeaders, "Schedule details must be under 200 characters.", 400);
    }
    if (trimmedSchedule && !SAFE_TEXT_REGEX.test(trimmedSchedule)) {
      return jsonError(corsHeaders, "Schedule details contain invalid characters.", 400);
    }

    // ─── Validate work history 1 (required) ───
    if (!work_history_1.employer || !work_history_1.title || !work_history_1.duration || !work_history_1.reason_for_leaving) {
      return jsonError(corsHeaders, "All fields for most recent employer are required.", 400);
    }
    const wh1Fields = [work_history_1.employer, work_history_1.title, work_history_1.duration, work_history_1.reason_for_leaving];
    for (const f of wh1Fields) {
      if (f.trim().length > 150) return jsonError(corsHeaders, "Work history fields must be under 150 characters.", 400);
      if (!SAFE_TEXT_REGEX.test(f.trim())) return jsonError(corsHeaders, "Work history fields contain invalid characters.", 400);
    }

    // ─── Validate work history 2 (optional, but all-or-nothing) ───
    let hasWH2 = false;
    if (work_history_2 && work_history_2.employer && work_history_2.employer.trim()) {
      hasWH2 = true;
      if (!work_history_2.title || !work_history_2.title.trim() ||
          !work_history_2.duration || !work_history_2.duration.trim() ||
          !work_history_2.reason_for_leaving || !work_history_2.reason_for_leaving.trim()) {
        return jsonError(corsHeaders, "If you provide a second employer, all fields are required.", 400);
      }
      const wh2Fields = [work_history_2.employer, work_history_2.title, work_history_2.duration, work_history_2.reason_for_leaving];
      for (const f of wh2Fields) {
        if (f.trim().length > 150) return jsonError(corsHeaders, "Work history fields must be under 150 characters.", 400);
        if (!SAFE_TEXT_REGEX.test(f.trim())) return jsonError(corsHeaders, "Work history fields contain invalid characters.", 400);
      }
    }

    // ─── Validate references & additional (optional) ───
    const trimmedReferences = references ? references.trim() : "";
    const trimmedAdditional = additional ? additional.trim() : "";
    if (trimmedReferences.length > 1000) return jsonError(corsHeaders, "References must be under 1000 characters.", 400);
    if (trimmedAdditional.length > 1000) return jsonError(corsHeaders, "Additional info must be under 1000 characters.", 400);

    // ─── Build location display ───
    const locationDisplay = locations.map(s => LOCATION_DISPLAY[s] || s).join(", ");

    // ─── Send manager notification email ───
    if (env.RESEND_API_KEY && env.FROM_EMAIL && env.NOTIFY_EMAILS) {
      try {
        const subject = `New Application - ${position} - ${locationDisplay}`;

        let workHistory2Section = "";
        if (hasWH2) {
          workHistory2Section = `
Previous Employer:      ${work_history_2.employer.trim()}
Job Title:              ${work_history_2.title.trim()}
Duration:               ${work_history_2.duration.trim()}
Reason for Leaving:     ${work_history_2.reason_for_leaving.trim()}`;
        }

        const text = `
New Job Application

APPLICANT INFORMATION
─────────────────────────────
Full Name:          ${trimmedName}
Phone:              ${trimmedPhone}
Email:              ${trimmedEmail || "Not provided"}
Address:            ${trimmedAddress}

POSITION & LOCATION
─────────────────────────────
Position:           ${position}
Location(s):        ${locationDisplay}
Availability:       ${availability}
Schedule Details:   ${trimmedSchedule || "Not provided"}

WORK HISTORY
─────────────────────────────
Most Recent Employer:   ${work_history_1.employer.trim()}
Job Title:              ${work_history_1.title.trim()}
Duration:               ${work_history_1.duration.trim()}
Reason for Leaving:     ${work_history_1.reason_for_leaving.trim()}
${workHistory2Section}

REFERENCES
─────────────────────────────
${trimmedReferences || "Not provided"}

ADDITIONAL INFORMATION
─────────────────────────────
${trimmedAdditional || "Not provided"}

---
This is an automated notification from G&KK NAPA Careers.
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
            reply_to: trimmedEmail || "careers@gkk-napa.com",
            subject,
            text,
          }),
        });

        if (!emailResponse.ok) {
          const errBody = await emailResponse.text();
          console.error(JSON.stringify({ tag: "RESEND_MANAGER_EMAIL_ERROR", status: emailResponse.status, error: errBody }));
        } else {
          console.log(JSON.stringify({ tag: "RESEND_MANAGER_EMAIL_SENT", subject, applicant: trimmedName }));
        }
      } catch (emailErr) {
        console.error(JSON.stringify({ tag: "RESEND_MANAGER_EMAIL_EXCEPTION", error: emailErr.message }));
      }

      // ─── Send applicant confirmation email (if email provided) ───
      if (trimmedEmail) {
        try {
          const applicantSubject = "We received your application - G&KK NAPA Auto Parts";
          const applicantText = `
Hi ${trimmedName},

Thank you for applying to G&KK NAPA Auto Parts! We've received your application and wanted to confirm the details:

Position: ${position}
Location(s): ${locationDisplay}
Availability: ${availability}

What happens next:
- Our management team will review your application within a few business days.
- If your qualifications match our current needs, we'll reach out by phone to schedule an interview.
- Feel free to call any of our stores if you have questions.

Our Stores:
- Danville, IL: (217) 446-9067
- Cayuga, IN: (765) 487-1324
- Rockville, IN: (765) 569-2011
- Covington, IN: (765) 793-2258

Thank you for your interest in joining our team!

G&KK NAPA Auto Parts
https://gkk-napa.com
`.trim();

          const applicantEmailResponse = await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: {
              Authorization: `Bearer ${env.RESEND_API_KEY}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              from: env.FROM_EMAIL,
              to: [trimmedEmail],
              reply_to: "info@gkk-napa.com",
              subject: applicantSubject,
              text: applicantText,
            }),
          });

          if (!applicantEmailResponse.ok) {
            const errBody = await applicantEmailResponse.text();
            console.error(JSON.stringify({ tag: "RESEND_APPLICANT_EMAIL_ERROR", status: applicantEmailResponse.status, error: errBody }));
          } else {
            console.log(JSON.stringify({ tag: "RESEND_APPLICANT_EMAIL_SENT", to: trimmedEmail, applicant: trimmedName }));
          }
        } catch (emailErr) {
          console.error(JSON.stringify({ tag: "RESEND_APPLICANT_EMAIL_EXCEPTION", error: emailErr.message }));
        }
      }
    }

    return new Response(
      JSON.stringify({ success: true }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (err) {
    console.error("Error:", err);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
}

function jsonError(corsHeaders, message, status) {
  return new Response(
    JSON.stringify({ error: message }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );
}
