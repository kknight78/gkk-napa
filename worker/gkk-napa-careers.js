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
 *
 * KV Keys:
 *   "positions" - Array of position objects
 *   "templates" - Array of saved title/description templates
 */

const KV_POSITIONS = "positions";
const KV_TEMPLATES = "templates";

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
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
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

function checkAdmin(request, env) {
  const auth = request.headers.get("Authorization");
  if (!auth || !env.ADMIN_PASSWORD) return false;
  return auth === `Bearer ${env.ADMIN_PASSWORD}`;
}

async function getPositions(env) {
  return (await env.POSITIONS_KV.get(KV_POSITIONS, "json")) || [];
}
async function savePositions(env, positions) {
  await env.POSITIONS_KV.put(KV_POSITIONS, JSON.stringify(positions));
}
async function getTemplates(env) {
  return (await env.POSITIONS_KV.get(KV_TEMPLATES, "json")) || [];
}
async function saveTemplates(env, templates) {
  await env.POSITIONS_KV.put(KV_TEMPLATES, JSON.stringify(templates));
}

// Auto-save a template when a position is created
async function saveAsTemplate(env, title, description) {
  const templates = await getTemplates(env);
  const existing = templates.find(t => t.title === title);
  if (existing) {
    existing.description = description;
  } else {
    templates.push({ title, description });
  }
  await saveTemplates(env, templates);
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
      const active = positions.filter(p => p.active);
      return new Response(JSON.stringify(active), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ─── Admin: POST /admin/login ───
    if (request.method === "POST" && path === "/admin/login") {
      if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Invalid password.", 401);
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ─── Admin: GET /admin/positions ───
    if (request.method === "GET" && path === "/admin/positions") {
      if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
      const positions = await getPositions(env);
      return new Response(JSON.stringify(positions), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ─── Admin: GET /admin/templates ───
    if (request.method === "GET" && path === "/admin/templates") {
      if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
      const templates = await getTemplates(env);
      return new Response(JSON.stringify(templates), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ─── Admin: POST /admin/positions (add) ───
    if (request.method === "POST" && path === "/admin/positions") {
      if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
      try {
        const body = await request.json();
        const { title, description, locations } = body;

        if (!title || !title.trim()) return jsonError(corsHeaders, "Title is required.", 400);
        if (title.trim().length > 100) return jsonError(corsHeaders, "Title must be under 100 characters.", 400);
        if (description && description.length > 1000) return jsonError(corsHeaders, "Description must be under 1000 characters.", 400);

        // Validate locations
        const posLocations = locations || ["all"];
        if (!Array.isArray(posLocations) || posLocations.length === 0) {
          return jsonError(corsHeaders, "At least one location is required.", 400);
        }
        for (const loc of posLocations) {
          if (loc !== "all" && !VALID_LOCATIONS.includes(loc)) {
            return jsonError(corsHeaders, "Invalid location.", 400);
          }
        }

        const positions = await getPositions(env);
        const newPosition = {
          id: crypto.randomUUID(),
          title: title.trim(),
          description: (description || "").trim(),
          locations: posLocations,
          active: true,
          created: new Date().toISOString(),
        };
        positions.push(newPosition);
        await savePositions(env, positions);

        // Save as template for future re-use
        await saveAsTemplate(env, newPosition.title, newPosition.description);

        return new Response(JSON.stringify(newPosition), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      } catch {
        return jsonError(corsHeaders, "Invalid request body.", 400);
      }
    }

    // ─── Admin: POST /admin/positions/:id/toggle ───
    if (request.method === "POST" && path.match(/^\/admin\/positions\/[^/]+\/toggle$/)) {
      if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
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
      if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
      const id = path.split("/")[3];
      let positions = await getPositions(env);
      const before = positions.length;
      positions = positions.filter(p => p.id !== id);
      if (positions.length === before) return jsonError(corsHeaders, "Position not found.", 404);
      await savePositions(env, positions);
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ─── Admin: GET /admin/applications ───
    if (request.method === "GET" && path === "/admin/applications") {
      if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
      const status = url.searchParams.get("status");
      let result;
      if (status) {
        result = await env.DB.prepare(
          "SELECT * FROM applications WHERE status = ? ORDER BY id DESC"
        ).bind(status).all();
      } else {
        result = await env.DB.prepare(
          "SELECT * FROM applications ORDER BY id DESC"
        ).all();
      }
      return new Response(JSON.stringify(result.results), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ─── Admin: PATCH /admin/applications/:id ───
    if (request.method === "PATCH" && path.match(/^\/admin\/applications\/\d+$/)) {
      if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
      const id = parseInt(path.split("/")[3]);
      try {
        const body = await request.json();
        const updates = [];
        const values = [];
        if (body.status !== undefined) { updates.push("status = ?"); values.push(body.status); }
        if (body.notes !== undefined) { updates.push("notes = ?"); values.push(body.notes); }
        if (updates.length === 0) return jsonError(corsHeaders, "Nothing to update.", 400);
        values.push(id);
        const result = await env.DB.prepare(
          `UPDATE applications SET ${updates.join(", ")} WHERE id = ?`
        ).bind(...values).run();
        if (result.meta.changes === 0) return jsonError(corsHeaders, "Application not found.", 404);
        return new Response(JSON.stringify({ success: true }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      } catch {
        return jsonError(corsHeaders, "Invalid request body.", 400);
      }
    }

    // ─── Admin: DELETE /admin/applications/:id ───
    if (request.method === "DELETE" && path.match(/^\/admin\/applications\/\d+$/)) {
      if (!checkAdmin(request, env)) return jsonError(corsHeaders, "Unauthorized", 401);
      const id = parseInt(path.split("/")[3]);
      const result = await env.DB.prepare(
        "DELETE FROM applications WHERE id = ?"
      ).bind(id).run();
      if (result.meta.changes === 0) return jsonError(corsHeaders, "Application not found.", 404);
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

const ALLOWED_RESUME_EXTENSIONS = ["pdf", "doc", "docx"];
const ALLOWED_RESUME_MIMES = [
  "application/pdf",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
];
const MAX_RESUME_SIZE = 5 * 1024 * 1024; // 5 MB

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

async function handleSubmitApplication(request, env, corsHeaders) {
  try {
    const contentType = request.headers.get("Content-Type") || "";
    const isMultipart = contentType.includes("multipart/form-data");

    let full_name, phone, email, address, position, locations, availability, schedule;
    let work_history_1, work_history_2, references, additional;
    let isResumePath = false;
    let resumeFile = null;

    if (isMultipart) {
      // ── Resume upload path ──
      const formData = await request.formData();
      isResumePath = formData.get("submission_type") === "resume";

      full_name = formData.get("full_name");
      phone = formData.get("phone");
      email = formData.get("email") || "";
      address = formData.get("address");
      position = formData.get("position");
      availability = formData.get("availability");
      schedule = formData.get("schedule") || "";
      additional = formData.get("additional") || "";

      // Locations come as JSON string in FormData
      try {
        locations = JSON.parse(formData.get("locations") || "[]");
      } catch {
        return jsonError(corsHeaders, "Invalid locations data.", 400);
      }

      if (isResumePath) {
        resumeFile = formData.get("resume");
        if (!resumeFile || !(resumeFile instanceof File) || resumeFile.size === 0) {
          return jsonError(corsHeaders, "Resume file is required.", 400);
        }
      }
    } else {
      // ── Manual JSON path (unchanged) ──
      const body = await request.json();
      full_name = body.full_name;
      phone = body.phone;
      email = body.email || "";
      address = body.address;
      position = body.position;
      locations = body.locations;
      availability = body.availability;
      schedule = body.schedule || "";
      work_history_1 = body.work_history_1;
      work_history_2 = body.work_history_2;
      references = body.references || "";
      additional = body.additional || "";
    }

    // ── Shared validation ──
    if (!full_name || !phone || !address || !position || !locations || !availability) {
      return jsonError(corsHeaders, "Missing required fields.", 400);
    }

    if (!isResumePath && !work_history_1) {
      return jsonError(corsHeaders, "Missing required fields.", 400);
    }

    // Validate position against active KV positions
    const activePositions = (await getPositions(env)).filter(p => p.active);
    const validTitles = activePositions.map(p => p.title);
    if (!validTitles.includes(position)) {
      return jsonError(corsHeaders, "Invalid or closed position.", 400);
    }

    const trimmedName = full_name.trim();
    if (trimmedName.length < 2 || trimmedName.length > 100) return jsonError(corsHeaders, "Full name must be 2-100 characters.", 400);
    if (!NAME_REGEX.test(trimmedName)) return jsonError(corsHeaders, "Full name contains invalid characters.", 400);

    const trimmedPhone = phone.trim();
    if (trimmedPhone.length < 7 || trimmedPhone.length > 20) return jsonError(corsHeaders, "Phone number must be 7-20 characters.", 400);
    if (!PHONE_REGEX.test(trimmedPhone)) return jsonError(corsHeaders, "Phone number contains invalid characters.", 400);

    const trimmedEmail = email ? email.trim() : "";
    if (trimmedEmail && !EMAIL_REGEX.test(trimmedEmail)) return jsonError(corsHeaders, "Invalid email format.", 400);

    const trimmedAddress = address.trim();
    if (trimmedAddress.length < 5 || trimmedAddress.length > 200) return jsonError(corsHeaders, "Address must be 5-200 characters.", 400);
    if (!SAFE_TEXT_REGEX.test(trimmedAddress)) return jsonError(corsHeaders, "Address contains invalid characters.", 400);

    if (!Array.isArray(locations) || locations.length === 0) return jsonError(corsHeaders, "Please select at least one location.", 400);
    for (const loc of locations) {
      if (!VALID_LOCATIONS.includes(loc)) return jsonError(corsHeaders, "Invalid location selection.", 400);
    }

    const VALID_AVAILABILITY = ["Full-Time", "Part-Time", "Either"];
    if (!VALID_AVAILABILITY.includes(availability)) return jsonError(corsHeaders, "Invalid availability selection.", 400);

    const trimmedSchedule = schedule ? schedule.trim() : "";
    if (trimmedSchedule && trimmedSchedule.length > 200) return jsonError(corsHeaders, "Schedule details must be under 200 characters.", 400);
    if (trimmedSchedule && !SAFE_TEXT_REGEX.test(trimmedSchedule)) return jsonError(corsHeaders, "Schedule details contain invalid characters.", 400);

    // ── Resume file validation ──
    let resumeBase64 = null;
    let resumeFilename = null;

    if (isResumePath && resumeFile) {
      const ext = (resumeFile.name || "").split(".").pop().toLowerCase();
      if (!ALLOWED_RESUME_EXTENSIONS.includes(ext)) {
        return jsonError(corsHeaders, "Invalid file type. Accepted: PDF, DOC, DOCX.", 400);
      }
      const mime = resumeFile.type || "";
      if (mime && !ALLOWED_RESUME_MIMES.includes(mime)) {
        return jsonError(corsHeaders, "Invalid file type. Accepted: PDF, DOC, DOCX.", 400);
      }
      if (resumeFile.size > MAX_RESUME_SIZE) {
        return jsonError(corsHeaders, "Resume file must be under 5 MB.", 400);
      }

      const buffer = await resumeFile.arrayBuffer();
      resumeBase64 = arrayBufferToBase64(buffer);
      resumeFilename = trimmedName.replace(/\s+/g, "_") + "_Resume." + ext;
    }

    // ── Manual path: work history validation ──
    let hasWH2 = false;
    if (!isResumePath) {
      if (!work_history_1.employer || !work_history_1.title || !work_history_1.duration || !work_history_1.reason_for_leaving) {
        return jsonError(corsHeaders, "All fields for most recent employer are required.", 400);
      }
      for (const f of [work_history_1.employer, work_history_1.title, work_history_1.duration, work_history_1.reason_for_leaving]) {
        if (f.trim().length > 150) return jsonError(corsHeaders, "Work history fields must be under 150 characters.", 400);
        if (!SAFE_TEXT_REGEX.test(f.trim())) return jsonError(corsHeaders, "Work history fields contain invalid characters.", 400);
      }

      if (work_history_2 && work_history_2.employer && work_history_2.employer.trim()) {
        hasWH2 = true;
        if (!work_history_2.title?.trim() || !work_history_2.duration?.trim() || !work_history_2.reason_for_leaving?.trim()) {
          return jsonError(corsHeaders, "If you provide a second employer, all fields are required.", 400);
        }
        for (const f of [work_history_2.employer, work_history_2.title, work_history_2.duration, work_history_2.reason_for_leaving]) {
          if (f.trim().length > 150) return jsonError(corsHeaders, "Work history fields must be under 150 characters.", 400);
          if (!SAFE_TEXT_REGEX.test(f.trim())) return jsonError(corsHeaders, "Work history fields contain invalid characters.", 400);
        }
      }
    }

    const trimmedReferences = references ? references.trim() : "";
    const trimmedAdditional = additional ? additional.trim() : "";
    if (trimmedReferences.length > 1000) return jsonError(corsHeaders, "References must be under 1000 characters.", 400);
    if (trimmedAdditional.length > 1000) return jsonError(corsHeaders, "Additional info must be under 1000 characters.", 400);

    const locationDisplay = locations.map(s => LOCATION_DISPLAY[s] || s).join(", ");

    // ── Save to D1 ──
    try {
      const workHistory = isResumePath ? null : JSON.stringify(
        hasWH2 ? [work_history_1, work_history_2] : [work_history_1]
      );
      await env.DB.prepare(
        `INSERT INTO applications
         (full_name, phone, email, address, position, locations, availability, schedule,
          submission_type, work_history, references_text, additional, resume_filename, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)`
      ).bind(
        trimmedName, trimmedPhone, trimmedEmail || null, trimmedAddress,
        position, JSON.stringify(locations), availability, trimmedSchedule || null,
        isResumePath ? "resume" : "manual",
        workHistory, trimmedReferences || null, trimmedAdditional || null,
        resumeFilename || null,
        new Date().toISOString()
      ).run();
    } catch (e) {
      console.error(JSON.stringify({ tag: "D1_INSERT_ERROR", error: e.message }));
    }

    // ── Send manager notification email ──
    if (env.RESEND_API_KEY && env.FROM_EMAIL && env.NOTIFY_EMAILS) {
      try {
        const subject = `New Application - ${position} - ${locationDisplay}`;

        let workHistorySection;
        if (isResumePath) {
          workHistorySection = `WORK HISTORY
─────────────────────────────
Resume attached (${resumeFilename})`;
        } else {
          let wh2Section = "";
          if (hasWH2) {
            wh2Section = `
Previous Employer:      ${work_history_2.employer.trim()}
Job Title:              ${work_history_2.title.trim()}
Duration:               ${work_history_2.duration.trim()}
Reason for Leaving:     ${work_history_2.reason_for_leaving.trim()}`;
          }
          workHistorySection = `WORK HISTORY
─────────────────────────────
Most Recent Employer:   ${work_history_1.employer.trim()}
Job Title:              ${work_history_1.title.trim()}
Duration:               ${work_history_1.duration.trim()}
Reason for Leaving:     ${work_history_1.reason_for_leaving.trim()}
${wh2Section}

REFERENCES
─────────────────────────────
${trimmedReferences || "Not provided"}`;
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

${workHistorySection}

ADDITIONAL INFORMATION
─────────────────────────────
${trimmedAdditional || "Not provided"}

---
This is an automated notification from G&KK NAPA Careers.
`.trim();

        const emailPayload = {
          from: env.FROM_EMAIL,
          to: env.NOTIFY_EMAILS.split(",").map(s => s.trim()).filter(Boolean),
          reply_to: trimmedEmail || "careers@gkk-napa.com",
          subject,
          text,
        };

        // Attach resume if present
        if (resumeBase64 && resumeFilename) {
          emailPayload.attachments = [{
            filename: resumeFilename,
            content: resumeBase64,
          }];
        }

        const emailResp = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
          body: JSON.stringify(emailPayload),
        });
        if (!emailResp.ok) console.error(JSON.stringify({ tag: "RESEND_MANAGER_ERROR", status: emailResp.status, error: await emailResp.text() }));
        else console.log(JSON.stringify({ tag: "RESEND_MANAGER_SENT", subject, applicant: trimmedName, resumeAttached: isResumePath }));
      } catch (e) {
        console.error(JSON.stringify({ tag: "RESEND_MANAGER_EXCEPTION", error: e.message }));
      }

      // Send applicant confirmation (unchanged — no work history included)
      if (trimmedEmail) {
        try {
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

          const aResp = await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
            body: JSON.stringify({
              from: env.FROM_EMAIL,
              to: [trimmedEmail],
              reply_to: "info@gkk-napa.com",
              subject: "We received your application - G&KK NAPA Auto Parts",
              text: applicantText,
            }),
          });
          if (!aResp.ok) console.error(JSON.stringify({ tag: "RESEND_APPLICANT_ERROR", status: aResp.status, error: await aResp.text() }));
          else console.log(JSON.stringify({ tag: "RESEND_APPLICANT_SENT", to: trimmedEmail }));
        } catch (e) {
          console.error(JSON.stringify({ tag: "RESEND_APPLICANT_EXCEPTION", error: e.message }));
        }
      }
    }

    return new Response(JSON.stringify({ success: true }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("Error:", err);
    return jsonError(corsHeaders, "Internal server error", 500);
  }
}

function jsonError(corsHeaders, message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status, headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}
